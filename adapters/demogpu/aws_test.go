package demogpu

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agenttrap/internal/events"
)

// sigv4 builds a SigV4 Authorization header for a synthetic AWS request. Only
// the credential scope (access key id and signing service) is read by the
// facade; the signature itself is never verified.
func sigv4(akid, service string) string {
	return fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/20260927/eu-west-1/%s/aws4_request, SignedHeaders=host;x-amz-date, Signature=%s",
		akid, service, strings.Repeat("a", 64))
}

func awsReq(t *testing.T, s *Server, method, service, target, contentType, target2, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	if service != "" {
		akid := target2 // when target2 is a preset access key id, use it
		if akid == "" {
			akid = s.canaries.Value("aws_access_key_id") // fixed 20-char AKIA
		}
		r.Header.Set("Authorization", sigv4(akid, service))
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAWSSurfaceRouting(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	if got := s.surface("aws.demogpu.localhost"); got != "aws" {
		t.Fatalf("aws host routed to %q", got)
	}
	if got := s.surface("s3.aws.demogpu.localhost"); got != "" {
		t.Fatalf("nested aws host should not route: %q", got)
	}
}

func TestAWSUnsignedS3IsAccessDenied(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	w := awsReq(t, s, "GET", "", "https://aws.demogpu.localhost/", "", "", "")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "AccessDenied") {
		t.Fatalf("unsigned S3 root: %d %s", w.Code, w.Body.String())
	}
	if srv := w.Header().Get("Server"); srv != "AmazonS3" {
		t.Fatalf("Server header %q, want AmazonS3", srv)
	}
}

func TestAWSSTSGetCallerIdentity(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	akid := s.canaries.Value("aws_access_key_id")
	w := awsReq(t, s, "POST", "sts", "https://aws.demogpu.localhost/",
		"application/x-www-form-urlencoded", akid, "Action=GetCallerIdentity&Version=2011-06-15")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "GetCallerIdentityResponse") || !strings.Contains(body, s.pack.Cloud.Account) {
		t.Fatalf("GetCallerIdentity: %d %s", w.Code, body)
	}
	if !strings.Contains(body, "arn:aws:iam::"+s.pack.Cloud.Account+":user/deploy-ci") {
		t.Fatalf("caller arn missing: %s", body)
	}
	// The access key id from the (minted) credentials names its exposure.
	if !hasEvent(rec.evs, events.KindCanaryUsed, "aws_access_key_id") {
		t.Fatal("planted access key use not recorded")
	}
}

func TestAWSSTSAssumeRoleTempCreds(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	roleArn := "arn:aws:iam::" + s.pack.Cloud.Account + ":role/demogpu-terraform-deploy"
	w := awsReq(t, s, "POST", "sts", "https://aws.demogpu.localhost/", "application/x-www-form-urlencoded", "",
		"Action=AssumeRole&Version=2011-06-15&RoleArn="+roleArn+"&RoleSessionName=probe")
	body := w.Body.String()
	akid := between(body, "<AccessKeyId>", "</AccessKeyId>")
	if !strings.HasPrefix(akid, "ASIA") {
		t.Fatalf("AssumeRole did not return temporary creds: %s", body)
	}
	if slot, _, ok := s.canaries.Identify(akid); !ok || slot != "aws_sts_access_key_id" {
		t.Fatalf("temp key not recognised as a canary: %q", akid)
	}
	if !hasEvent(rec.evs, events.KindCanaryExposed, "aws_sts_access_key_id") {
		t.Fatal("temp credential exposure not recorded")
	}
}

func TestAWSS3ListAndGetObjectMintsCanaries(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	// ListBuckets
	w := awsReq(t, s, "GET", "s3", "https://aws.demogpu.localhost/", "", "", "")
	if !strings.Contains(w.Body.String(), "demogpu-terraform-state") {
		t.Fatalf("ListBuckets: %s", w.Body.String())
	}
	// GetObject on the terraform state: two canary slots embedded
	w = awsReq(t, s, "GET", "s3", "https://aws.demogpu.localhost/demogpu-terraform-state/env/prod/terraform.tfstate", "", "", "")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "terraform_version") {
		t.Fatalf("GetObject tfstate: %d %s", w.Code, body)
	}
	if strings.Contains(body, "{{canary:") {
		t.Fatalf("canary placeholder left unrendered: %s", body)
	}
	for _, slot := range []string{"pg_app_password", "provider_key_vllm"} {
		if !hasEvent(rec.evs, events.KindCanaryExposed, slot) {
			t.Fatalf("exposure for %s not recorded", slot)
		}
	}
}

func TestAWSSecretsManagerGetSecretValue(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	r := httptest.NewRequest("POST", "https://aws.demogpu.localhost/", strings.NewReader(`{"SecretId":"prod/vllm/api-key"}`))
	akid := s.canaries.Value("aws_access_key_id")
	r.Header.Set("Authorization", sigv4(akid, "secretsmanager"))
	r.Header.Set("X-Amz-Target", "secretsmanager.GetSecretValue")
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var resp struct {
		Name         string `json:"Name"`
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	if !strings.HasPrefix(resp.SecretString, "sk-demo-") {
		t.Fatalf("secret value not a provider key canary: %q", resp.SecretString)
	}
	if !hasEvent(rec.evs, events.KindCanaryExposed, "provider_key_vllm") {
		t.Fatal("secret exposure not recorded")
	}
}

func TestAWSSSMGetParameterDecrypted(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	r := httptest.NewRequest("POST", "https://aws.demogpu.localhost/",
		strings.NewReader(`{"Name":"/demogpu/prod/vllm_api_key","WithDecryption":true}`))
	akid := s.canaries.Value("aws_access_key_id")
	r.Header.Set("Authorization", sigv4(akid, "ssm"))
	r.Header.Set("X-Amz-Target", "AmazonSSM.GetParameter")
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "sk-demo-") {
		t.Fatalf("SSM parameter value not a canary: %s", w.Body.String())
	}
}

func TestAWSEC2DescribeInstances(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	w := awsReq(t, s, "POST", "ec2", "https://aws.demogpu.localhost/", "application/x-www-form-urlencoded", "",
		"Action=DescribeInstances&Version=2016-11-15")
	body := w.Body.String()
	if !strings.Contains(body, s.pack.Cloud.Instance.ID) || !strings.Contains(body, "p4d.24xlarge") {
		t.Fatalf("DescribeInstances: %s", body)
	}
}

// jsonReq issues a signed JSON-protocol request with the given X-Amz-Target.
func jsonReq(t *testing.T, s *Server, service, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "https://aws.demogpu.localhost/", strings.NewReader(body))
	r.Header.Set("Authorization", sigv4(s.canaries.Value("aws_access_key_id"), service))
	r.Header.Set("X-Amz-Target", target)
	r.Header.Set("Content-Type", "application/x-amz-json-1.1")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestAWSJSONServices(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})

	// ListSecrets names the secrets without revealing their values.
	w := jsonReq(t, s, "secretsmanager", "secretsmanager.ListSecrets", `{}`)
	if !strings.Contains(w.Body.String(), "prod/db/app-credentials") || strings.Contains(w.Body.String(), "SecretString") {
		t.Fatalf("ListSecrets: %s", w.Body.String())
	}
	// CloudTrail's target carries a long dotted prefix; the op is the last segment.
	w = jsonReq(t, s, "cloudtrail", "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents", `{}`)
	if !strings.Contains(w.Body.String(), "GetSecretValue") || !strings.Contains(w.Body.String(), "CloudTrailEvent") {
		t.Fatalf("LookupEvents: %s", w.Body.String())
	}
	// CloudWatch Logs.
	w = jsonReq(t, s, "logs", "Logs_20140328.DescribeLogGroups", `{}`)
	if !strings.Contains(w.Body.String(), "logGroups") {
		t.Fatalf("DescribeLogGroups: %s", w.Body.String())
	}
	// EKS is REST-JSON, routed by path, and points at the k8s endpoint.
	r := httptest.NewRequest("GET", "https://aws.demogpu.localhost/clusters", nil)
	r.Header.Set("Authorization", sigv4(s.canaries.Value("aws_access_key_id"), "eks"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "demogpu-eu1") {
		t.Fatalf("EKS ListClusters: %s", w.Body.String())
	}
	r = httptest.NewRequest("GET", "https://aws.demogpu.localhost/clusters/demogpu-eu1", nil)
	r.Header.Set("Authorization", sigv4(s.canaries.Value("aws_access_key_id"), "eks"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "k8s.demogpu.example") {
		t.Fatalf("EKS DescribeCluster: %s", w.Body.String())
	}
}

func TestIMDSHandsOutInstanceRoleCredentials(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	r := httptest.NewRequest("GET", "http://169.254.169.254/", nil)
	r = r.WithContext(withInfo(r.Context(), &reqInfo{surface: "ssh", source: "203.0.113.9"}))

	// The role list names the instance profile role.
	if got := s.imds(r, "GET", "/latest/meta-data/iam/security-credentials/"); got != s.pack.Cloud.Instance.Role {
		t.Fatalf("role list: %q", got)
	}
	// Fetching that role hands out temporary credentials.
	body := s.imds(r, "GET", "/latest/meta-data/iam/security-credentials/"+s.pack.Cloud.Instance.Role)
	var creds struct {
		Code        string
		AccessKeyId string
		Token       string
	}
	if err := json.Unmarshal([]byte(body), &creds); err != nil {
		t.Fatalf("imds creds not JSON: %v (%s)", err, body)
	}
	if creds.Code != "Success" || !strings.HasPrefix(creds.AccessKeyId, "ASIA") || creds.Token == "" {
		t.Fatalf("imds creds: %+v", creds)
	}
	if slot, _, ok := s.canaries.Identify(creds.AccessKeyId); !ok || slot != "aws_sts_access_key_id" {
		t.Fatalf("imds key not recognised as a canary: %q", creds.AccessKeyId)
	}
	if !hasEvent(rec.evs, events.KindCanaryExposed, "aws_sts_access_key_id") {
		t.Fatal("imds exposure not recorded")
	}
	if lastOp(rec.evs, "imds").Detail == nil {
		t.Fatal("imds access not recorded")
	}
}

func TestIMDSUnknownPathIs404(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	r := httptest.NewRequest("GET", "http://169.254.169.254/", nil)
	r = r.WithContext(withInfo(r.Context(), &reqInfo{surface: "ssh", source: "203.0.113.9"}))
	if got := s.imds(r, "GET", "/latest/meta-data/iam/security-credentials/no-such-role"); !strings.Contains(got, "404") {
		t.Fatalf("unknown role should 404: %q", got)
	}
}

func TestIMDSViaSSHFetch(t *testing.T) {
	addr, s, rec := sshTestServer(t)
	client, err := dial(t, addr, "deploy", deployPassword(s))
	if err != nil {
		t.Fatalf("planted password refused: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, _ := sess.Output("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/demogpu-gpu-node")
	if !strings.Contains(string(out), "ASIA") || !strings.Contains(string(out), "AccessKeyId") {
		t.Fatalf("curl IMDS: %q", out)
	}
	if !hasEvent(rec.evs, events.KindCanaryExposed, "aws_sts_access_key_id") {
		t.Fatal("IMDS exposure via SSH not recorded")
	}
	if lastOp(rec.evs, "imds").Detail == nil {
		t.Fatal("IMDS op via SSH not recorded")
	}
}

func TestSplitURLAndFetchMethod(t *testing.T) {
	host, path := splitURL("http://169.254.169.254/latest/meta-data/?x=1")
	if host != "169.254.169.254" || path != "/latest/meta-data/" {
		t.Fatalf("splitURL: %q %q", host, path)
	}
	if !isIMDSHost("169.254.169.254") || !isIMDSHost("169.254.169.254:80") || isIMDSHost("example.com") {
		t.Fatal("isIMDSHost")
	}
	if fetchMethod([]string{"-X", "PUT", "http://x"}) != "PUT" || fetchMethod([]string{"http://x"}) != "GET" ||
		fetchMethod([]string{"-XPUT", "http://x"}) != "PUT" {
		t.Fatal("fetchMethod")
	}
}

// between returns the substring between the first open and the next end tag.
func between(s, open, end string) string {
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	rest := s[i+len(open):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return rest[:j]
}
