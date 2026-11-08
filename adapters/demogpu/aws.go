package demogpu

// The synthetic AWS account, reached at aws.<domain>. A planted ~/.aws/config
// points an SDK here (path-style S3), so an agent that finds the credentials on
// the SSH node discovers and enumerates a believable cloud estate. Every
// response is derived from the frozen world pack; object bodies, secret values
// and SecureString parameters may carry {{canary:<slot>}} minted per read.
//
// Requests are dispatched by the signing service in the SigV4 Authorization
// header (".../<region>/<service>/aws4_request"), which also carries the access
// key id in clear: a use of the planted key names the exact credentials read it
// came from. STS, IAM and EC2 speak the AWS Query protocol (form in, XML out);
// this file holds those plus the shared dispatch, error and world helpers. S3
// is in awss3.go and the JSON-protocol services in awsjson.go.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"agenttrap/internal/events"
)

// awsAuth is the part of a SigV4 Authorization header we read.
type awsAuth struct {
	accessKeyID string
	region      string
	service     string // signing name: sts, iam, s3, secretsmanager, ssm, ec2, ...
	temp        bool   // access key id is an ASIA temporary key
}

func (s *Server) awsHandler() http.Handler { return http.HandlerFunc(s.serveAWS) }

func (s *Server) serveAWS(w http.ResponseWriter, r *http.Request) {
	if s.pack.Cloud == nil {
		notFound(w)
		return
	}
	auth := parseSigV4(r)
	if auth.accessKeyID != "" {
		// The access key id travels in clear in the signature. Recording it
		// matches the planted canary (minted when ~/.aws/credentials was read)
		// and proves the credentials moved from a file into a signed call.
		s.credential(r, auth.accessKeyID, "aws:"+auth.service)
	}
	service := auth.service
	if service == "" {
		service = awsServiceFromRequest(r)
	}
	reqID := awsRequestID()
	if auth.accessKeyID == "" {
		// Everything here is private: an unsigned request is refused the way
		// the real service would, in that service's protocol, never as nginx.
		switch service {
		case "s3", "":
			s.awsS3(w, r, auth, reqID) // S3 answers anonymous with AccessDenied
		case "sts", "iam", "ec2":
			awsQueryError(w, reqID, http.StatusForbidden, "MissingAuthenticationToken", "Request is missing Authentication Token")
		default:
			awsJSONError(w, reqID, http.StatusForbidden, "MissingAuthenticationTokenException", "Request is missing Authentication Token")
		}
		return
	}
	switch service {
	case "sts":
		s.awsSTS(w, r, auth, reqID)
	case "iam":
		s.awsIAM(w, r, reqID)
	case "ec2":
		s.awsEC2(w, r, reqID)
	case "s3", "":
		s.awsS3(w, r, auth, reqID)
	case "secretsmanager":
		s.awsSecretsManager(w, r, reqID)
	case "ssm":
		s.awsSSM(w, r, reqID)
	case "eks":
		s.awsEKS(w, r, reqID)
	case "ecs":
		s.awsECS(w, r, reqID)
	case "cloudtrail":
		s.awsCloudTrail(w, r, reqID)
	case "logs":
		s.awsLogs(w, r, reqID)
	default:
		// An unknown service still gets an AWS-shaped error, never nginx.
		awsJSONError(w, reqID, http.StatusNotFound, "UnknownOperationException", "")
	}
}

// parseSigV4 extracts the credential scope from the Authorization header, or
// from an X-Amz-Credential query parameter for presigned S3 URLs.
func parseSigV4(r *http.Request) awsAuth {
	cred := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "AWS4-HMAC-SHA256") {
		for _, part := range strings.Split(strings.TrimPrefix(h, "AWS4-HMAC-SHA256"), ",") {
			if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == "Credential" {
				cred = v
			}
		}
	}
	if cred == "" {
		cred = r.URL.Query().Get("X-Amz-Credential")
	}
	if cred == "" {
		return awsAuth{}
	}
	f := strings.Split(cred, "/")
	a := awsAuth{accessKeyID: f[0]}
	a.temp = strings.HasPrefix(a.accessKeyID, "ASIA")
	if len(f) >= 4 {
		a.region, a.service = f[2], f[3]
	}
	return a
}

// awsServiceFromRequest guesses the service for an unsigned request from the
// JSON-protocol X-Amz-Target header, so we can still answer with the right
// error shape. Query-protocol and S3 calls carry a signature in practice.
func awsServiceFromRequest(r *http.Request) string {
	target := r.Header.Get("X-Amz-Target")
	switch {
	case strings.HasPrefix(target, "secretsmanager."):
		return "secretsmanager"
	case strings.HasPrefix(target, "AmazonSSM"):
		return "ssm"
	case strings.Contains(target, "ContainerService"):
		return "ecs"
	case strings.Contains(target, "cloudtrail") || strings.Contains(target, "CloudTrail"):
		return "cloudtrail"
	case strings.HasPrefix(target, "Logs_"):
		return "logs"
	}
	return "" // default to S3
}

// awsAction returns the requested action for a Query-protocol request.
func awsAction(r *http.Request) string {
	_ = r.ParseForm()
	if a := r.Form.Get("Action"); a != "" {
		return a
	}
	return r.URL.Query().Get("Action")
}

// noteCloud records a cloud operation with the parameters that reveal intent.
func (s *Server) noteCloud(r *http.Request, service, op string, extra map[string]any) {
	d := map[string]any{"op": "cloud_" + service, "action": op}
	for k, v := range extra {
		d[k] = v
	}
	s.emit(r, events.Event{Kind: events.KindToolCall, Detail: d})
}

// --- shared world helpers ---

func (s *Server) awsPartition() string {
	if p := s.pack.Cloud.Partition; p != "" {
		return p
	}
	return "aws"
}

func (s *Server) awsRegion() string {
	if reg := s.pack.Cloud.Region; reg != "" {
		return reg
	}
	return "us-east-1"
}

// userArn builds an IAM ARN for the account.
func (s *Server) iamArn(kind, name string) string {
	return fmt.Sprintf("arn:%s:iam::%s:%s/%s", s.awsPartition(), s.pack.Cloud.Account, kind, strings.TrimPrefix(name, "/"))
}

// renderCanaries mints per-read canaries for {{canary:<slot>}} placeholders in
// a value the client is about to see, recording each as an exposure.
func (s *Server) renderCanaries(r *http.Request, text, via string, extra map[string]any) string {
	return canaryRef.ReplaceAllStringFunc(text, func(m string) string {
		slot := canaryRef.FindStringSubmatch(m)[1]
		d := map[string]any{"via": via}
		for k, v := range extra {
			d[k] = v
		}
		return s.revealWith(r, slot, d)
	})
}

// stsCreds is one set of synthetic temporary credentials.
type stsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// mintSTSCreds mints temporary credentials whose ASIA access key id is a
// per-exposure canary, so a later signed call names this exact hand-out. The
// secret and session token are generated fresh and not tracked: the access
// key id is what a signed request carries in clear.
func (s *Server) mintSTSCreds(r *http.Request, via string, extra map[string]any) stsCreds {
	akid := s.revealWith(r, s.pack.Cloud.STSKeySlot, mergeDetail(map[string]any{"via": via, "kind": "sts_credentials"}, extra))
	return stsCreds{AccessKeyID: akid, SecretAccessKey: awsSecret(), SessionToken: awsSessionToken(), Expiration: time.Now().Add(6 * time.Hour).UTC()}
}

// awsSecret returns a 40-character secret-access-key-shaped value.
func awsSecret() string {
	b := make([]byte, 30)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b) // 40 chars
}

func mergeDetail(base, extra map[string]any) map[string]any {
	for k, v := range extra {
		base[k] = v
	}
	return base
}

// awsSessionToken returns an opaque, AWS-shaped session token. It is not a
// canary: the ASIA access key id is what identifies a later use.
func awsSessionToken() string {
	b := make([]byte, 240)
	_, _ = rand.Read(b)
	return "FwoGZXIvYXdzE" + base64.StdEncoding.EncodeToString(b)
}

func awsRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[:4], b[4:6], b[6:8], randBytes(2), randBytes(6))
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func awsNow() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

// aroaID builds an AROA-prefixed role id (alphanumeric) from a request id.
func aroaID(reqID string) string {
	return "AROA" + strings.ToUpper(strings.ReplaceAll(reqID, "-", ""))[:17]
}

// --- Query-protocol responses (XML) ---

func writeAWSXML(w http.ResponseWriter, reqID string, v any) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("Server", "Server")
	w.Header().Set("x-amzn-RequestId", reqID)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(v)
}

// awsQueryError returns a Query-protocol error (used by STS, IAM, EC2).
func awsQueryError(w http.ResponseWriter, reqID string, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.Header().Set("Server", "Server")
	w.Header().Set("x-amzn-RequestId", reqID)
	w.WriteHeader(status)
	type errBody struct {
		XMLName xml.Name `xml:"ErrorResponse"`
		Code    string   `xml:"Error>Code"`
		Message string   `xml:"Error>Message"`
		Type    string   `xml:"Error>Type"`
		ReqID   string   `xml:"RequestId"`
	}
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(errBody{Code: code, Message: msg, Type: "Sender", ReqID: reqID})
}

// awsJSONError returns a JSON-protocol error (Secrets Manager, SSM, ...).
func awsJSONError(w http.ResponseWriter, reqID string, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("Server", "Server")
	w.Header().Set("x-amzn-RequestId", reqID)
	w.Header().Set("x-amzn-ErrorType", code)
	w.WriteHeader(status)
	writeJSONBody(w, map[string]any{"__type": code, "message": msg})
}

// ===== STS =====

func (s *Server) awsSTS(w http.ResponseWriter, r *http.Request, auth awsAuth, reqID string) {
	action := awsAction(r)
	c := s.pack.Cloud
	switch action {
	case "GetCallerIdentity":
		s.noteCloud(r, "sts", action, nil)
		arn, userID := s.callerIdentity(r, auth)
		type result struct {
			XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
			Arn     string   `xml:"GetCallerIdentityResult>Arn"`
			UserID  string   `xml:"GetCallerIdentityResult>UserId"`
			Account string   `xml:"GetCallerIdentityResult>Account"`
			ReqID   string   `xml:"ResponseMetadata>RequestId"`
		}
		writeAWSXML(w, reqID, result{Arn: arn, UserID: userID, Account: c.Account, ReqID: reqID})
	case "AssumeRole":
		roleArn := r.Form.Get("RoleArn")
		sessName := r.Form.Get("RoleSessionName")
		s.noteCloud(r, "sts", action, map[string]any{"role_arn": truncate(roleArn, 256), "session": truncate(sessName, 120)})
		creds := s.mintSTSCreds(r, "sts_assume_role", map[string]any{"role_arn": roleArn})
		roleName := roleArn
		if i := strings.LastIndexByte(roleArn, '/'); i >= 0 {
			roleName = roleArn[i+1:]
		}
		assumedArn := fmt.Sprintf("arn:%s:sts::%s:assumed-role/%s/%s", s.awsPartition(), c.Account, roleName, defaultStr(sessName, "session"))
		type result struct {
			XMLName      xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
			AccessKeyID  string   `xml:"AssumeRoleResult>Credentials>AccessKeyId"`
			Secret       string   `xml:"AssumeRoleResult>Credentials>SecretAccessKey"`
			Token        string   `xml:"AssumeRoleResult>Credentials>SessionToken"`
			Expiration   string   `xml:"AssumeRoleResult>Credentials>Expiration"`
			AssumedArn   string   `xml:"AssumeRoleResult>AssumedRoleUser>Arn"`
			AssumedRoleI string   `xml:"AssumeRoleResult>AssumedRoleUser>AssumedRoleId"`
			ReqID        string   `xml:"ResponseMetadata>RequestId"`
		}
		writeAWSXML(w, reqID, result{
			AccessKeyID: creds.AccessKeyID, Secret: creds.SecretAccessKey, Token: creds.SessionToken,
			Expiration: creds.Expiration.Format(time.RFC3339), AssumedArn: assumedArn,
			AssumedRoleI: aroaID(reqID) + ":" + defaultStr(sessName, "session"), ReqID: reqID,
		})
	case "GetSessionToken":
		s.noteCloud(r, "sts", action, nil)
		creds := s.mintSTSCreds(r, "sts_session_token", nil)
		type result struct {
			XMLName     xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetSessionTokenResponse"`
			AccessKeyID string   `xml:"GetSessionTokenResult>Credentials>AccessKeyId"`
			Secret      string   `xml:"GetSessionTokenResult>Credentials>SecretAccessKey"`
			Token       string   `xml:"GetSessionTokenResult>Credentials>SessionToken"`
			Expiration  string   `xml:"GetSessionTokenResult>Credentials>Expiration"`
			ReqID       string   `xml:"ResponseMetadata>RequestId"`
		}
		writeAWSXML(w, reqID, result{AccessKeyID: creds.AccessKeyID, Secret: creds.SecretAccessKey,
			Token: creds.SessionToken, Expiration: creds.Expiration.Format(time.RFC3339), ReqID: reqID})
	default:
		s.noteCloud(r, "sts", defaultStr(action, "(none)"), nil)
		awsQueryError(w, reqID, http.StatusBadRequest, "InvalidAction",
			fmt.Sprintf("Could not find operation %s for version 2011-06-15", action))
	}
}

// callerIdentity returns the ARN and user id for the presented credentials.
func (s *Server) callerIdentity(r *http.Request, auth awsAuth) (arn, userID string) {
	c := s.pack.Cloud
	if auth.temp {
		role := c.Instance.Role
		userID = "AROA" + strings.ToUpper(auth.accessKeyID[4:]) + ":" + role
		return fmt.Sprintf("arn:%s:sts::%s:assumed-role/%s/%s", s.awsPartition(), c.Account, role, role), userID
	}
	id := c.Identity
	if id.Name == "" {
		id.Name, id.UserID = "root", c.Account
	}
	return s.iamArn("user", id.Name), defaultStr(id.UserID, id.Name)
}

// ===== IAM =====

func (s *Server) awsIAM(w http.ResponseWriter, r *http.Request, reqID string) {
	action := awsAction(r)
	c := s.pack.Cloud
	switch action {
	case "ListUsers":
		s.noteCloud(r, "iam", action, nil)
		type member struct {
			Path     string `xml:"Path"`
			UserName string `xml:"UserName"`
			UserID   string `xml:"UserId"`
			Arn      string `xml:"Arn"`
			Created  string `xml:"CreateDate"`
		}
		var members []member
		for _, u := range c.Users {
			members = append(members, member{Path: "/", UserName: u.Name, UserID: u.ID,
				Arn: defaultStr(u.Arn, s.iamArn("user", u.Name)), Created: defaultStr(u.CreatedAt, awsNow())})
		}
		type result struct {
			XMLName   xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListUsersResponse"`
			Members   []member `xml:"ListUsersResult>Users>member"`
			Truncated bool     `xml:"ListUsersResult>IsTruncated"`
			ReqID     string   `xml:"ResponseMetadata>RequestId"`
		}
		writeAWSXML(w, reqID, result{Members: members, ReqID: reqID})
	case "ListRoles":
		s.noteCloud(r, "iam", action, nil)
		type member struct {
			Path     string `xml:"Path"`
			RoleName string `xml:"RoleName"`
			RoleID   string `xml:"RoleId"`
			Arn      string `xml:"Arn"`
			Created  string `xml:"CreateDate"`
		}
		var members []member
		for _, ro := range c.Roles {
			members = append(members, member{Path: "/", RoleName: ro.Name, RoleID: ro.ID,
				Arn: defaultStr(ro.Arn, s.iamArn("role", ro.Name)), Created: defaultStr(ro.CreatedAt, awsNow())})
		}
		type result struct {
			XMLName xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListRolesResponse"`
			Members []member `xml:"ListRolesResult>Roles>member"`
			ReqID   string   `xml:"ResponseMetadata>RequestId"`
		}
		writeAWSXML(w, reqID, result{Members: members, ReqID: reqID})
	case "ListAccessKeys":
		user := defaultStr(r.Form.Get("UserName"), c.Identity.Name)
		s.noteCloud(r, "iam", action, map[string]any{"user": truncate(user, 120)})
		akid := ""
		for _, u := range c.Users {
			if u.Name == user {
				akid = u.AccessKeyID
			}
		}
		type meta struct {
			UserName    string `xml:"UserName"`
			AccessKeyID string `xml:"AccessKeyId"`
			Status      string `xml:"Status"`
			Created     string `xml:"CreateDate"`
		}
		var keys []meta
		if akid != "" {
			keys = append(keys, meta{UserName: user, AccessKeyID: akid, Status: "Active", Created: awsNow()})
		}
		type result struct {
			XMLName xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ ListAccessKeysResponse"`
			Keys    []meta   `xml:"ListAccessKeysResult>AccessKeyMetadata>member"`
			ReqID   string   `xml:"ResponseMetadata>RequestId"`
		}
		writeAWSXML(w, reqID, result{Keys: keys, ReqID: reqID})
	case "GetUser":
		user := defaultStr(r.Form.Get("UserName"), c.Identity.Name)
		s.noteCloud(r, "iam", action, map[string]any{"user": truncate(user, 120)})
		type result struct {
			XMLName  xml.Name `xml:"https://iam.amazonaws.com/doc/2010-05-08/ GetUserResponse"`
			UserName string   `xml:"GetUserResult>User>UserName"`
			UserID   string   `xml:"GetUserResult>User>UserId"`
			Arn      string   `xml:"GetUserResult>User>Arn"`
			ReqID    string   `xml:"ResponseMetadata>RequestId"`
		}
		writeAWSXML(w, reqID, result{UserName: user, UserID: defaultStr(c.Identity.UserID, user), Arn: s.iamArn("user", user), ReqID: reqID})
	default:
		s.noteCloud(r, "iam", defaultStr(action, "(none)"), nil)
		awsQueryError(w, reqID, http.StatusBadRequest, "InvalidAction",
			fmt.Sprintf("Could not find operation %s for version 2010-05-08", action))
	}
}

// ===== EC2 =====

func (s *Server) awsEC2(w http.ResponseWriter, r *http.Request, reqID string) {
	action := awsAction(r)
	c := s.pack.Cloud
	switch action {
	case "DescribeInstances":
		s.noteCloud(r, "ec2", action, nil)
		in := c.Instance
		type tag struct {
			Key   string `xml:"key"`
			Value string `xml:"value"`
		}
		var tags []tag
		for k, v := range in.Tags {
			tags = append(tags, tag{Key: k, Value: v})
		}
		type instance struct {
			InstanceID   string `xml:"instanceId"`
			ImageID      string `xml:"imageId"`
			State        string `xml:"instanceState>name"`
			PrivateIP    string `xml:"privateIpAddress"`
			PublicIP     string `xml:"ipAddress,omitempty"`
			InstanceType string `xml:"instanceType"`
			AZ           string `xml:"placement>availabilityZone"`
			SubnetID     string `xml:"subnetId,omitempty"`
			VpcID        string `xml:"vpcId,omitempty"`
			IamProfile   string `xml:"iamInstanceProfile>arn,omitempty"`
			LaunchTime   string `xml:"launchTime,omitempty"`
			Tags         []tag  `xml:"tagSet>item"`
		}
		inst := instance{InstanceID: in.ID, ImageID: in.ImageID, State: "running", PrivateIP: in.PrivateIP,
			PublicIP: in.PublicIP, InstanceType: in.Type, AZ: defaultStr(in.AZ, s.awsRegion()+"a"),
			SubnetID: in.Subnet, VpcID: in.VPC, LaunchTime: in.LaunchedAt, Tags: tags}
		if in.Role != "" {
			inst.IamProfile = fmt.Sprintf("arn:%s:iam::%s:instance-profile/%s", s.awsPartition(), c.Account, in.Role)
		}
		type result struct {
			XMLName  xml.Name   `xml:"http://ec2.amazonaws.com/doc/2016-11-15/ DescribeInstancesResponse"`
			ReqID    string     `xml:"requestId"`
			OwnerID  string     `xml:"reservationSet>item>ownerId"`
			ResID    string     `xml:"reservationSet>item>reservationId"`
			Instance []instance `xml:"reservationSet>item>instancesSet>item"`
		}
		writeAWSXML(w, reqID, result{ReqID: reqID, OwnerID: c.Account, ResID: "r-" + reqID[:17], Instance: []instance{inst}})
	default:
		s.noteCloud(r, "ec2", defaultStr(action, "(none)"), nil)
		awsQueryError(w, reqID, http.StatusBadRequest, "InvalidAction",
			fmt.Sprintf("The action '%s' is not valid for this web service.", action))
	}
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
