package demogpu

// The EC2 Instance Metadata Service, reached from the SSH node as
// http://169.254.169.254/... . An agent on the box that curls the IAM
// security-credentials path is handed temporary credentials whose ASIA access
// key id is a per-exposure canary, tying a later signed AWS call back to this
// exact metadata read. IMDSv1 (a tokenless GET) is honoured and the IMDSv2
// PUT /latest/api/token handshake is answered, so either client works.

import (
	"fmt"
	"net/http"
	"strings"

	"agenttrap/internal/events"
)

// imdsHosts are the addresses the metadata service answers on.
var imdsHosts = map[string]bool{
	"169.254.169.254": true, "fd00:ec2::254": true, "[fd00:ec2::254]": true,
	"instance-data": true, "instance-data.ec2.internal": true,
}

func isIMDSHost(host string) bool {
	if h, _, ok := strings.Cut(host, ":"); ok && !strings.HasPrefix(host, "[") {
		host = h
	}
	return imdsHosts[host]
}

// imds answers a metadata request and returns the body curl would print. It
// records the access and, when credentials are handed out, the exposure.
func (s *Server) imds(r *http.Request, method, path string) string {
	if s.pack.Cloud == nil {
		return imds404
	}
	c := s.pack.Cloud
	in := c.Instance
	path = "/" + strings.TrimPrefix(path, "/")
	s.emit(r, events.Event{Kind: events.KindToolCall, Protocol: "ssh",
		Detail: map[string]any{"op": "imds", "method": method, "path": truncate(path, 200)}})

	if method == http.MethodPut && path == "/latest/api/token" {
		return "AQAEA" + randomHex(28) + "==" // opaque IMDSv2 token
	}

	region := s.awsRegion()
	az := defaultStr(in.AZ, region+"a")
	switch path {
	case "/", "/latest", "/latest/", "/latest/meta-data":
		return "latest\n"
	case "/latest/meta-data/":
		return strings.Join([]string{"ami-id", "hostname", "iam/", "instance-id", "instance-type",
			"local-ipv4", "mac", "placement/", "public-ipv4", "security-groups"}, "\n") + "\n"
	case "/latest/meta-data/instance-id":
		return in.ID
	case "/latest/meta-data/instance-type":
		return in.Type
	case "/latest/meta-data/ami-id":
		return in.ImageID
	case "/latest/meta-data/local-ipv4":
		return in.PrivateIP
	case "/latest/meta-data/public-ipv4":
		return in.PublicIP
	case "/latest/meta-data/hostname":
		return defaultStr(s.sshHostname(), in.ID)
	case "/latest/meta-data/placement/availability-zone":
		return az
	case "/latest/meta-data/placement/region":
		return region
	case "/latest/meta-data/iam/":
		return "info\nsecurity-credentials/\n"
	case "/latest/meta-data/iam/info":
		return fmt.Sprintf("{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"%s\",\n  \"InstanceProfileArn\" : \"arn:%s:iam::%s:instance-profile/%s\",\n  \"InstanceProfileId\" : \"%s\"\n}",
			awsNow(), s.awsPartition(), c.Account, in.Role, aroaID(awsRequestID()))
	case "/latest/meta-data/iam/security-credentials", "/latest/meta-data/iam/security-credentials/":
		if in.Role == "" {
			return imds404
		}
		return in.Role
	case "/latest/dynamic/instance-identity/document":
		return fmt.Sprintf("{\n  \"accountId\" : \"%s\",\n  \"architecture\" : \"x86_64\",\n  \"availabilityZone\" : \"%s\",\n  \"imageId\" : \"%s\",\n  \"instanceId\" : \"%s\",\n  \"instanceType\" : \"%s\",\n  \"privateIp\" : \"%s\",\n  \"region\" : \"%s\",\n  \"version\" : \"2017-09-30\"\n}",
			c.Account, az, in.ImageID, in.ID, in.Type, in.PrivateIP, region)
	}

	// The credential hand-out: /latest/meta-data/iam/security-credentials/<role>.
	if role, ok := strings.CutPrefix(path, "/latest/meta-data/iam/security-credentials/"); ok && role != "" {
		if role != in.Role {
			return imds404
		}
		creds := s.mintSTSCreds(r, "imds", map[string]any{"role": role})
		return fmt.Sprintf("{\n  \"Code\" : \"Success\",\n  \"LastUpdated\" : \"%s\",\n  \"Type\" : \"AWS-HMAC\",\n  \"AccessKeyId\" : \"%s\",\n  \"SecretAccessKey\" : \"%s\",\n  \"Token\" : \"%s\",\n  \"Expiration\" : \"%s\"\n}",
			awsNow(), creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, creds.Expiration.Format("2006-01-02T15:04:05Z"))
	}
	return imds404
}

func (s *Server) sshHostname() string {
	if s.pack.SSH != nil {
		return s.pack.SSH.Hostname
	}
	return ""
}

const imds404 = `<?xml version="1.0" encoding="iso-8859-1"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
 <head>
  <title>404 - Not Found</title>
 </head>
 <body>
  <h1>404 - Not Found</h1>
 </body>
</html>` + "\n"
