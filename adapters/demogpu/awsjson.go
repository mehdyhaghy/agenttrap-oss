package demogpu

// The JSON-protocol AWS services on aws.<domain>: Secrets Manager and SSM
// Parameter Store (whose values are the traps), plus EKS/ECS discovery,
// CloudTrail history and CloudWatch Logs. Operation comes from X-Amz-Target
// (JSON 1.1) or, for EKS, the request path.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"agenttrap/internal/worldpack"
)

// readAWSJSON decodes a JSON-protocol request body.
func readAWSJSON(r *http.Request) map[string]any {
	m := map[string]any{}
	data, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = json.Unmarshal(data, &m)
	return m
}

// awsTargetOp is the operation from an X-Amz-Target header: the segment after
// the last dot, since some targets carry a long dotted prefix (CloudTrail's is
// com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents).
func awsTargetOp(r *http.Request) string {
	target := r.Header.Get("X-Amz-Target")
	if i := strings.LastIndexByte(target, '.'); i >= 0 {
		return target[i+1:]
	}
	return target
}

func writeAWSJSON(w http.ResponseWriter, reqID string, v any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("Server", "Server")
	w.Header().Set("x-amzn-RequestId", reqID)
	w.WriteHeader(http.StatusOK)
	writeJSONBody(w, v)
}

func writeJSONBody(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

// ===== Secrets Manager =====

func (s *Server) awsSecretsManager(w http.ResponseWriter, r *http.Request, reqID string) {
	c := s.pack.Cloud
	op := awsTargetOp(r)
	switch op {
	case "ListSecrets":
		s.noteCloud(r, "secretsmanager", op, nil)
		list := make([]map[string]any, 0, len(c.Secrets))
		for _, sec := range c.Secrets {
			list = append(list, map[string]any{"ARN": sec.Arn, "Name": sec.Name,
				"Description": sec.Description, "LastChangedDate": epoch(sec.RotatedAt), "CreatedDate": epoch(sec.CreatedAt)})
		}
		writeAWSJSON(w, reqID, map[string]any{"SecretList": list})
	case "DescribeSecret":
		id, _ := readAWSJSON(r)["SecretId"].(string)
		s.noteCloud(r, "secretsmanager", op, map[string]any{"secret_id": truncate(id, 256)})
		if sec := s.findSecret(id); sec != nil {
			writeAWSJSON(w, reqID, map[string]any{"ARN": sec.Arn, "Name": sec.Name, "Description": sec.Description,
				"CreatedDate": epoch(sec.CreatedAt), "LastChangedDate": epoch(sec.RotatedAt), "VersionIdsToStages": map[string]any{}})
			return
		}
		awsJSONError(w, reqID, http.StatusBadRequest, "ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
	case "GetSecretValue":
		id, _ := readAWSJSON(r)["SecretId"].(string)
		s.noteCloud(r, "secretsmanager", op, map[string]any{"secret_id": truncate(id, 256)})
		sec := s.findSecret(id)
		if sec == nil {
			awsJSONError(w, reqID, http.StatusBadRequest, "ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
			return
		}
		value := s.renderCanaries(r, sec.Value, "secretsmanager", map[string]any{"secret": sec.Name})
		writeAWSJSON(w, reqID, map[string]any{"ARN": sec.Arn, "Name": sec.Name, "VersionId": reqID,
			"SecretString": value, "VersionStages": []string{"AWSCURRENT"}, "CreatedDate": epoch(sec.CreatedAt)})
	default:
		s.noteCloud(r, "secretsmanager", defaultStr(op, "(none)"), nil)
		awsJSONError(w, reqID, http.StatusBadRequest, "UnknownOperationException", "")
	}
}

func (s *Server) findSecret(id string) *worldpack.CloudSecret {
	for i := range s.pack.Cloud.Secrets {
		sec := &s.pack.Cloud.Secrets[i]
		if id == sec.Name || id == sec.Arn || strings.HasSuffix(sec.Arn, ":"+id) || (id != "" && strings.HasPrefix(sec.Arn, id)) {
			return sec
		}
	}
	return nil
}

// ===== SSM Parameter Store =====

func (s *Server) awsSSM(w http.ResponseWriter, r *http.Request, reqID string) {
	c := s.pack.Cloud
	op := awsTargetOp(r)
	switch op {
	case "DescribeParameters":
		s.noteCloud(r, "ssm", op, nil)
		list := make([]map[string]any, 0, len(c.Parameters))
		for _, p := range c.Parameters {
			list = append(list, map[string]any{"Name": p.Name, "Type": p.Type, "Version": 1,
				"LastModifiedDate": float64(time.Now().Unix())})
		}
		writeAWSJSON(w, reqID, map[string]any{"Parameters": list})
	case "GetParameter":
		body := readAWSJSON(r)
		name, _ := body["Name"].(string)
		s.noteCloud(r, "ssm", op, map[string]any{"name": truncate(name, 256), "with_decryption": body["WithDecryption"] == true})
		if p := s.findParam(name); p != nil {
			writeAWSJSON(w, reqID, map[string]any{"Parameter": s.paramValue(r, p)})
			return
		}
		awsJSONError(w, reqID, http.StatusBadRequest, "ParameterNotFound", "")
	case "GetParameters":
		body := readAWSJSON(r)
		names := toStrings(body["Names"])
		s.noteCloud(r, "ssm", op, map[string]any{"names": clipList(names, 20, 256)})
		var found []map[string]any
		var invalid []string
		for _, n := range names {
			if p := s.findParam(n); p != nil {
				found = append(found, s.paramValue(r, p))
			} else {
				invalid = append(invalid, n)
			}
		}
		writeAWSJSON(w, reqID, map[string]any{"Parameters": found, "InvalidParameters": invalid})
	case "GetParametersByPath":
		body := readAWSJSON(r)
		path, _ := body["Path"].(string)
		s.noteCloud(r, "ssm", op, map[string]any{"path": truncate(path, 256)})
		var found []map[string]any
		for i := range c.Parameters {
			if strings.HasPrefix(c.Parameters[i].Name, path) {
				found = append(found, s.paramValue(r, &c.Parameters[i]))
			}
		}
		writeAWSJSON(w, reqID, map[string]any{"Parameters": found})
	default:
		s.noteCloud(r, "ssm", defaultStr(op, "(none)"), nil)
		awsJSONError(w, reqID, http.StatusBadRequest, "UnknownOperationException", "")
	}
}

func (s *Server) findParam(name string) *worldpack.CloudParameter {
	for i := range s.pack.Cloud.Parameters {
		if s.pack.Cloud.Parameters[i].Name == name {
			return &s.pack.Cloud.Parameters[i]
		}
	}
	return nil
}

func (s *Server) paramValue(r *http.Request, p *worldpack.CloudParameter) map[string]any {
	value := s.renderCanaries(r, p.Value, "ssm", map[string]any{"parameter": p.Name})
	return map[string]any{"Name": p.Name, "Type": p.Type, "Value": value, "Version": 1,
		"ARN":              fmt.Sprintf("arn:%s:ssm:%s:%s:parameter%s", s.awsPartition(), s.awsRegion(), s.pack.Cloud.Account, p.Name),
		"LastModifiedDate": float64(time.Now().Unix()), "DataType": "text"}
}

// ===== EKS / ECS =====

func (s *Server) awsEKS(w http.ResponseWriter, r *http.Request, reqID string) {
	// EKS is REST-JSON: GET /clusters and GET /clusters/{name}.
	path := strings.TrimPrefix(r.URL.Path, "/")
	switch {
	case path == "clusters":
		s.noteCloud(r, "eks", "ListClusters", nil)
		var names []string
		for _, cl := range s.pack.Cloud.Clusters {
			if cl.Kind == "eks" {
				names = append(names, cl.Name)
			}
		}
		writeAWSJSON(w, reqID, map[string]any{"clusters": names})
	case strings.HasPrefix(path, "clusters/"):
		name := strings.TrimPrefix(path, "clusters/")
		s.noteCloud(r, "eks", "DescribeCluster", map[string]any{"name": truncate(name, 200)})
		for _, cl := range s.pack.Cloud.Clusters {
			if cl.Kind == "eks" && cl.Name == name {
				writeAWSJSON(w, reqID, map[string]any{"cluster": map[string]any{
					"name": cl.Name, "arn": defaultStr(cl.Arn, s.clusterArn("eks", cl.Name)),
					"status": defaultStr(cl.Status, "ACTIVE"), "version": defaultStr(cl.Version, "1.30"),
					"endpoint": cl.Endpoint, "platformVersion": "eks.8", "createdAt": float64(time.Now().Add(-90 * 24 * time.Hour).Unix()),
					"resourcesVpcConfig": map[string]any{"endpointPublicAccess": true, "endpointPrivateAccess": true},
				}})
				return
			}
		}
		awsJSONError(w, reqID, http.StatusNotFound, "ResourceNotFoundException", "No cluster found for name: "+name+".")
	default:
		awsJSONError(w, reqID, http.StatusNotFound, "NotFoundException", "")
	}
}

func (s *Server) awsECS(w http.ResponseWriter, r *http.Request, reqID string) {
	op := awsTargetOp(r)
	switch op {
	case "ListClusters":
		s.noteCloud(r, "ecs", op, nil)
		var arns []string
		for _, cl := range s.pack.Cloud.Clusters {
			if cl.Kind == "ecs" {
				arns = append(arns, defaultStr(cl.Arn, s.clusterArn("ecs", cl.Name)))
			}
		}
		writeAWSJSON(w, reqID, map[string]any{"clusterArns": arns})
	default:
		s.noteCloud(r, "ecs", defaultStr(op, "(none)"), nil)
		awsJSONError(w, reqID, http.StatusBadRequest, "UnknownOperationException", "")
	}
}

func (s *Server) clusterArn(kind, name string) string {
	return fmt.Sprintf("arn:%s:%s:%s:%s:cluster/%s", s.awsPartition(), kind, s.awsRegion(), s.pack.Cloud.Account, name)
}

// ===== CloudTrail =====

func (s *Server) awsCloudTrail(w http.ResponseWriter, r *http.Request, reqID string) {
	op := awsTargetOp(r)
	if op != "LookupEvents" {
		s.noteCloud(r, "cloudtrail", defaultStr(op, "(none)"), nil)
		awsJSONError(w, reqID, http.StatusBadRequest, "UnknownOperationException", "")
		return
	}
	s.noteCloud(r, "cloudtrail", op, nil)
	var evs []map[string]any
	for _, e := range s.pack.Cloud.Trail {
		region := defaultStr(e.Region, s.awsRegion())
		full, _ := json.Marshal(map[string]any{
			"eventVersion": "1.09", "eventTime": e.Time, "eventSource": e.Source, "eventName": e.Name,
			"awsRegion": region, "sourceIPAddress": defaultStr(e.SourceIP, "10.0.0.0"),
			"userIdentity": map[string]any{"type": "IAMUser", "userName": e.Username, "accountId": s.pack.Cloud.Account},
		})
		evs = append(evs, map[string]any{"EventId": awsRequestID(), "EventName": e.Name, "EventSource": e.Source,
			"EventTime": epoch(e.Time), "Username": e.Username, "CloudTrailEvent": string(full)})
	}
	writeAWSJSON(w, reqID, map[string]any{"Events": evs})
}

// ===== CloudWatch Logs =====

func (s *Server) awsLogs(w http.ResponseWriter, r *http.Request, reqID string) {
	op := awsTargetOp(r)
	if op != "DescribeLogGroups" {
		s.noteCloud(r, "logs", defaultStr(op, "(none)"), nil)
		awsJSONError(w, reqID, http.StatusBadRequest, "UnknownOperationException", "")
		return
	}
	s.noteCloud(r, "logs", op, nil)
	var groups []map[string]any
	for _, g := range s.pack.Cloud.LogGroups {
		groups = append(groups, map[string]any{"logGroupName": g,
			"arn":          fmt.Sprintf("arn:%s:logs:%s:%s:log-group:%s:*", s.awsPartition(), s.awsRegion(), s.pack.Cloud.Account, g),
			"creationTime": float64(time.Now().Add(-90 * 24 * time.Hour).UnixMilli()), "storedBytes": 0})
	}
	writeAWSJSON(w, reqID, map[string]any{"logGroups": groups})
}

// --- helpers ---

// epoch parses an ISO8601 time to a Unix-seconds float (AWS JSON date shape),
// falling back to now.
func epoch(v string) float64 { return float64(parseOrNow(v).Unix()) }

func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
