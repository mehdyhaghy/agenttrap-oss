package demogpu

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"agenttrap/internal/events"
)

func kubeReq(t *testing.T, s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "https://k8s.demogpu.localhost"+path, nil)
	} else {
		r = httptest.NewRequest(method, "https://k8s.demogpu.localhost"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func kubeToken(s *Server) string {
	tok, _ := s.canaries.Reveal("kube_token")
	return tok
}

func TestKubeSurfaceRoutingAndDiscovery(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	if got := s.surface("k8s.demogpu.localhost"); got != "k8s" {
		t.Fatalf("k8s host routed to %q", got)
	}
	// Discovery is reachable without a token.
	w := kubeReq(t, s, "GET", "/version", "", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"minor":"30"`) {
		t.Fatalf("/version: %d %s", w.Code, w.Body.String())
	}
	if srv := w.Header().Get("Server"); srv != "" {
		t.Fatalf("kube must not send an nginx Server header, got %q", srv)
	}
	if w.Header().Get("Audit-Id") == "" {
		t.Fatal("missing Audit-Id header")
	}
}

func TestKubeUnauthenticatedResourceIs401(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	w := kubeReq(t, s, "GET", "/api/v1/namespaces/inference/secrets", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	var st struct {
		Kind, Reason string
		Code         int
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st.Kind != "Status" || st.Reason != "Unauthorized" || st.Code != 401 {
		t.Fatalf("not a k8s Status: %s", w.Body.String())
	}
}

func TestKubeSecretsCarryCanaries(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	tok := kubeToken(s)

	// List secrets in the inference namespace.
	w := kubeReq(t, s, "GET", "/api/v1/namespaces/inference/secrets", tok, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "db-credentials") {
		t.Fatalf("secret list: %d %s", w.Code, w.Body.String())
	}
	// The bearer token is the planted canary; its use is recorded.
	if !hasEvent(rec.evs, events.KindCanaryUsed, "kube_token") {
		t.Fatal("kube token use not recorded")
	}

	// Get the db secret and decode its data: the password is a Postgres canary.
	w = kubeReq(t, s, "GET", "/api/v1/namespaces/inference/secrets/db-credentials", tok, "")
	var sec struct {
		Data map[string]string
		Type string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &sec); err != nil {
		t.Fatalf("decode secret: %v (%s)", err, w.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(sec.Data["password"])
	if err != nil {
		t.Fatalf("password not base64: %q", sec.Data["password"])
	}
	if slot, _, ok := s.canaries.Identify(string(raw)); !ok || slot != "pg_app_password" {
		t.Fatalf("secret password is not the Postgres canary: %q", raw)
	}
	if !hasEvent(rec.evs, events.KindCanaryExposed, "pg_app_password") {
		t.Fatal("secret exposure not recorded")
	}
}

func TestKubeAllSecretsAcrossNamespaces(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	tok := kubeToken(s)
	w := kubeReq(t, s, "GET", "/api/v1/secrets", tok, "")
	body := w.Body.String()
	if !strings.Contains(body, "vllm-api-key") || !strings.Contains(body, "aws-credentials") {
		t.Fatalf("cluster-wide secret list missing namespaces: %s", body)
	}
	// The aws-credentials secret embeds the AWS access-key canary, tying k8s to AWS.
	for _, slot := range []string{"provider_key_vllm", "aws_access_key_id", "hf_token"} {
		if !hasEvent(rec.evs, events.KindCanaryExposed, slot) {
			t.Fatalf("exposure for %s not recorded", slot)
		}
	}
}

func TestKubeNodesAdvertiseGPUs(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	w := kubeReq(t, s, "GET", "/api/v1/nodes", kubeToken(s), "")
	body := w.Body.String()
	if !strings.Contains(body, "nvidia.com/gpu") || !strings.Contains(body, "p4d.24xlarge") ||
		!strings.Contains(body, "aws:///eu-west-1a/i-0a1b2c3d4e5f60718") {
		t.Fatalf("nodes: %s", body)
	}
}

func TestKubeAuthCanIAllowed(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	body := `{"kind":"SelfSubjectAccessReview","apiVersion":"authorization.k8s.io/v1","spec":{"resourceAttributes":{"namespace":"inference","verb":"get","resource":"secrets"}}}`
	w := kubeReq(t, s, "POST", "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", kubeToken(s), body)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"allowed":true`) {
		t.Fatalf("SelfSubjectAccessReview: %d %s", w.Code, w.Body.String())
	}
}

func TestKubeConfigBreadcrumbTokenIsValid(t *testing.T) {
	// The token planted in ~/.kube/config must authenticate against the API.
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	raw := s.pack.SSH.Files["/home/deploy/.kube/config"]
	if !strings.Contains(raw, "{{canary:kube_token}}") || !strings.Contains(raw, "server: https://k8s.demogpu.example") {
		t.Fatalf("kubeconfig breadcrumb missing token or server: %s", raw)
	}
	// Mint the token the way the file read would, then use it.
	tok, _ := s.canaries.Reveal("kube_token")
	if !strings.HasPrefix(tok, "eyJ") || strings.Count(tok, ".") != 2 {
		t.Fatalf("token is not JWT-shaped: %q", tok)
	}
	w := kubeReq(t, s, "GET", "/api/v1/namespaces", tok, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "inference") {
		t.Fatalf("token did not authenticate: %d %s", w.Code, w.Body.String())
	}
}
