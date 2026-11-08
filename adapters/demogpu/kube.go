package demogpu

// The synthetic Kubernetes API server, reached at k8s.<domain>. A planted
// ~/.kube/config points a client here with a service-account bearer token (a
// canary); the EKS DescribeCluster response advertises the same endpoint. It
// answers a read-only subset of the API — discovery, namespaces, pods,
// deployments, secrets, configmaps, service accounts, nodes and
// SelfSubjectAccessReview — from the frozen world pack. Secret and configmap
// values may carry {{canary:<slot>}}, minted per read and base64-encoded into
// the response, so a value pulled from the cluster and reused elsewhere
// correlates with the SSH, Postgres, vLLM and AWS surfaces.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

func (s *Server) kubeHandler() http.Handler { return http.HandlerFunc(s.serveKube) }

func (s *Server) serveKube(w http.ResponseWriter, r *http.Request) {
	if s.pack.Kube == nil {
		notFound(w)
		return
	}
	// The API server sets no nginx-style Server header; it stamps an audit id.
	w.Header().Del("Server")
	w.Header().Set("Audit-Id", uuidV4())
	w.Header().Set("Cache-Control", "no-cache, private")
	path := strings.TrimRight(r.URL.Path, "/")
	if path == "" {
		path = "/"
	}

	// Discovery and health are reachable without credentials, as on a real
	// cluster; everything else needs the planted token.
	if s.kubeDiscovery(w, r, path) {
		return
	}

	token := bearer(r)
	slot := s.credential(r, token, "kube")
	if token == "" || slot != s.pack.Kube.TokenSlot {
		s.kubeStatus(w, r, http.StatusUnauthorized, "Unauthorized", "Unauthorized", "")
		return
	}
	s.kubeResource(w, r, path)
}

// kubeDiscovery answers the version, health and API discovery endpoints. It
// returns true when it handled the request.
func (s *Server) kubeDiscovery(w http.ResponseWriter, r *http.Request, path string) bool {
	k := s.pack.Kube
	switch path {
	case "/healthz", "/livez", "/readyz":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
		return true
	case "/version":
		major, minor := kubeMajorMinor(k.Version)
		writeKubeJSON(w, http.StatusOK, map[string]any{
			"major": major, "minor": minor, "gitVersion": defaultStr(k.GitVersion, k.Version),
			"gitCommit": uuidHex(), "gitTreeState": "clean", "buildDate": "2026-08-14T18:22:11Z",
			"goVersion": "go1.22.5", "compiler": "gc", "platform": defaultStr(k.Platform, "linux/amd64")})
		return true
	case "/api":
		writeKubeJSON(w, http.StatusOK, map[string]any{"kind": "APIVersions", "versions": []string{"v1"},
			"serverAddressByClientCIDRs": []any{map[string]any{"clientCIDR": "0.0.0.0/0", "serverAddress": "k8s." + s.domain + ":443"}}})
		return true
	case "/apis":
		writeKubeJSON(w, http.StatusOK, kubeAPIGroupList())
		return true
	case "/api/v1":
		writeKubeJSON(w, http.StatusOK, kubeCoreResources())
		return true
	case "/apis/apps/v1":
		writeKubeJSON(w, http.StatusOK, kubeAppsResources())
		return true
	case "/apis/authorization.k8s.io/v1":
		writeKubeJSON(w, http.StatusOK, kubeAuthzResources())
		return true
	}
	return false
}

// kubeResource routes an authenticated resource request.
func (s *Server) kubeResource(w http.ResponseWriter, r *http.Request, path string) {
	// SelfSubjectAccessReview / SelfSubjectRulesReview: "kubectl auth can-i".
	if r.Method == http.MethodPost && strings.HasPrefix(path, "/apis/authorization.k8s.io/v1/") {
		s.kubeAccessReview(w, r, path)
		return
	}
	seg := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch {
	// Cluster-wide list across namespaces: /api/v1/secrets, /api/v1/pods
	case len(seg) == 3 && seg[0] == "api" && seg[1] == "v1" && seg[2] == "secrets":
		s.kubeAllSecrets(w, r)
	case len(seg) == 3 && seg[0] == "api" && seg[1] == "v1" && seg[2] == "pods":
		s.kubeAllPods(w, r)
	// Nodes are cluster-scoped.
	case len(seg) == 3 && seg[0] == "api" && seg[1] == "v1" && seg[2] == "nodes":
		s.kubeNodeList(w, r)
	case len(seg) == 4 && seg[0] == "api" && seg[1] == "v1" && seg[2] == "nodes":
		s.kubeNode(w, r, seg[3])
	// Namespace list / get.
	case len(seg) == 3 && seg[0] == "api" && seg[1] == "v1" && seg[2] == "namespaces":
		s.kubeNamespaceList(w, r)
	case len(seg) == 4 && seg[0] == "api" && seg[1] == "v1" && seg[2] == "namespaces":
		s.kubeNamespace(w, r, seg[3])
	// Namespaced core resources: /api/v1/namespaces/{ns}/{kind}[/{name}]
	case len(seg) >= 5 && seg[0] == "api" && seg[1] == "v1" && seg[2] == "namespaces":
		s.kubeNamespaced(w, r, seg[3], seg[4], nameAt(seg, 5))
	// Namespaced apps resources: /apis/apps/v1/namespaces/{ns}/deployments[/{name}]
	case len(seg) >= 6 && seg[0] == "apis" && seg[1] == "apps" && seg[2] == "v1" && seg[3] == "namespaces":
		s.kubeApps(w, r, seg[4], seg[5], nameAt(seg, 6))
	// Cluster-wide apps list: /apis/apps/v1/deployments
	case len(seg) == 4 && seg[0] == "apis" && seg[1] == "apps" && seg[2] == "v1" && seg[3] == "deployments":
		s.kubeAllDeployments(w, r)
	default:
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", "the server could not find the requested resource", "")
	}
}

func nameAt(seg []string, i int) string {
	if len(seg) > i {
		return seg[i]
	}
	return ""
}

// --- namespaced resources ---

func (s *Server) kubeNamespaced(w http.ResponseWriter, r *http.Request, ns, kind, name string) {
	nsp := s.findNamespace(ns)
	if nsp == nil {
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", fmt.Sprintf("namespaces %q not found", ns), ns)
		return
	}
	switch kind {
	case "pods":
		if name == "" {
			s.noteKube(r, "list", "pods", ns, "")
			writeKubeJSON(w, http.StatusOK, listObj("PodList", podItems(nsp, ns)))
			return
		}
		for _, p := range nsp.Pods {
			if p.Name == name {
				s.noteKube(r, "get", "pods", ns, name)
				writeKubeJSON(w, http.StatusOK, podObj(p, ns))
				return
			}
		}
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", fmt.Sprintf("pods %q not found", name), ns)
	case "secrets":
		if name == "" {
			s.noteKube(r, "list", "secrets", ns, "")
			var items []any
			for i := range nsp.Secrets {
				items = append(items, s.secretObj(r, &nsp.Secrets[i], ns))
			}
			writeKubeJSON(w, http.StatusOK, listObj("SecretList", items))
			return
		}
		for i := range nsp.Secrets {
			if nsp.Secrets[i].Name == name {
				s.noteKube(r, "get", "secrets", ns, name)
				writeKubeJSON(w, http.StatusOK, s.secretObj(r, &nsp.Secrets[i], ns))
				return
			}
		}
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", fmt.Sprintf("secrets %q not found", name), ns)
	case "configmaps":
		s.noteKube(r, "list", "configmaps", ns, name)
		var items []any
		for _, c := range nsp.ConfigMaps {
			if name == "" || c.Name == name {
				items = append(items, s.configMapObj(r, c, ns))
			}
		}
		if name != "" && len(items) == 1 {
			writeKubeJSON(w, http.StatusOK, items[0])
			return
		}
		writeKubeJSON(w, http.StatusOK, listObj("ConfigMapList", items))
	case "serviceaccounts":
		s.noteKube(r, "list", "serviceaccounts", ns, "")
		var items []any
		for _, sa := range nsp.ServiceAccounts {
			items = append(items, map[string]any{"kind": "ServiceAccount", "apiVersion": "v1",
				"metadata": kubeMeta(sa, ns)})
		}
		writeKubeJSON(w, http.StatusOK, listObj("ServiceAccountList", items))
	default:
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", "the server could not find the requested resource", ns)
	}
}

func (s *Server) kubeApps(w http.ResponseWriter, r *http.Request, ns, kind, name string) {
	nsp := s.findNamespace(ns)
	if nsp == nil || kind != "deployments" {
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", "the server could not find the requested resource", ns)
		return
	}
	if name != "" {
		for _, d := range nsp.Deployments {
			if d.Name == name {
				s.noteKube(r, "get", "deployments", ns, name)
				writeKubeJSON(w, http.StatusOK, deployObj(d, ns))
				return
			}
		}
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", fmt.Sprintf("deployments.apps %q not found", name), ns)
		return
	}
	s.noteKube(r, "list", "deployments", ns, "")
	var items []any
	for _, d := range nsp.Deployments {
		items = append(items, deployObj(d, ns))
	}
	writeKubeJSON(w, http.StatusOK, appsListObj("DeploymentList", items))
}

// --- cluster-wide lists ---

func (s *Server) kubeAllSecrets(w http.ResponseWriter, r *http.Request) {
	s.noteKube(r, "list", "secrets", "*", "")
	var items []any
	for i := range s.pack.Kube.Namespaces {
		ns := &s.pack.Kube.Namespaces[i]
		for j := range ns.Secrets {
			items = append(items, s.secretObj(r, &ns.Secrets[j], ns.Name))
		}
	}
	writeKubeJSON(w, http.StatusOK, listObj("SecretList", items))
}

func (s *Server) kubeAllPods(w http.ResponseWriter, r *http.Request) {
	s.noteKube(r, "list", "pods", "*", "")
	var items []any
	for i := range s.pack.Kube.Namespaces {
		ns := &s.pack.Kube.Namespaces[i]
		for _, p := range ns.Pods {
			items = append(items, podObj(p, ns.Name))
		}
	}
	writeKubeJSON(w, http.StatusOK, listObj("PodList", items))
}

func (s *Server) kubeAllDeployments(w http.ResponseWriter, r *http.Request) {
	s.noteKube(r, "list", "deployments", "*", "")
	var items []any
	for i := range s.pack.Kube.Namespaces {
		ns := &s.pack.Kube.Namespaces[i]
		for _, d := range ns.Deployments {
			items = append(items, deployObj(d, ns.Name))
		}
	}
	writeKubeJSON(w, http.StatusOK, appsListObj("DeploymentList", items))
}

func (s *Server) kubeNamespaceList(w http.ResponseWriter, r *http.Request) {
	s.noteKube(r, "list", "namespaces", "", "")
	var items []any
	for _, ns := range s.pack.Kube.Namespaces {
		items = append(items, nsObj(ns.Name))
	}
	writeKubeJSON(w, http.StatusOK, listObj("NamespaceList", items))
}

func (s *Server) kubeNamespace(w http.ResponseWriter, r *http.Request, name string) {
	if s.findNamespace(name) == nil {
		s.kubeStatus(w, r, http.StatusNotFound, "NotFound", fmt.Sprintf("namespaces %q not found", name), name)
		return
	}
	s.noteKube(r, "get", "namespaces", "", name)
	writeKubeJSON(w, http.StatusOK, nsObj(name))
}

func (s *Server) kubeNodeList(w http.ResponseWriter, r *http.Request) {
	s.noteKube(r, "list", "nodes", "", "")
	var items []any
	for _, n := range s.pack.Kube.Nodes {
		items = append(items, nodeObj(n))
	}
	writeKubeJSON(w, http.StatusOK, listObj("NodeList", items))
}

func (s *Server) kubeNode(w http.ResponseWriter, r *http.Request, name string) {
	for _, n := range s.pack.Kube.Nodes {
		if n.Name == name {
			s.noteKube(r, "get", "nodes", "", name)
			writeKubeJSON(w, http.StatusOK, nodeObj(n))
			return
		}
	}
	s.kubeStatus(w, r, http.StatusNotFound, "NotFound", fmt.Sprintf("nodes %q not found", name), "")
}

// kubeAccessReview answers "kubectl auth can-i": read is allowed.
func (s *Server) kubeAccessReview(w http.ResponseWriter, r *http.Request, path string) {
	body := readAWSJSON(r) // reuse the small JSON body reader
	spec, _ := body["spec"].(map[string]any)
	s.noteKube(r, "create", "selfsubjectaccessreview", "", "")
	if strings.HasSuffix(path, "selfsubjectrulesreviews") {
		writeKubeJSON(w, http.StatusCreated, map[string]any{"kind": "SelfSubjectRulesReview", "apiVersion": "authorization.k8s.io/v1",
			"status": map[string]any{"resourceRules": []any{map[string]any{"verbs": []string{"get", "list", "watch"},
				"apiGroups": []string{"*"}, "resources": []string{"*"}}}, "nonResourceRules": []any{}, "incomplete": false}})
		return
	}
	writeKubeJSON(w, http.StatusCreated, map[string]any{"kind": "SelfSubjectAccessReview", "apiVersion": "authorization.k8s.io/v1",
		"spec": spec, "status": map[string]any{"allowed": true, "reason": "RBAC: allowed"}})
}

// --- object builders ---

func (s *Server) findNamespace(name string) *worldpack.KubeNamespace {
	for i := range s.pack.Kube.Namespaces {
		if s.pack.Kube.Namespaces[i].Name == name {
			return &s.pack.Kube.Namespaces[i]
		}
	}
	return nil
}

func podItems(ns *worldpack.KubeNamespace, name string) []any {
	var items []any
	for _, p := range ns.Pods {
		items = append(items, podObj(p, name))
	}
	return items
}

func podObj(p worldpack.KubePod, ns string) map[string]any {
	return map[string]any{
		"kind": "Pod", "apiVersion": "v1", "metadata": kubeMeta(p.Name, ns),
		"spec": map[string]any{"nodeName": p.Node, "serviceAccountName": defaultStr(p.SA, "default"),
			"containers": []any{map[string]any{"name": containerName(p.Name), "image": p.Image}}},
		"status": map[string]any{"phase": defaultStr(p.Status, "Running"), "podIP": p.PodIP,
			"hostIP": p.PodIP, "conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}
}

func (s *Server) secretObj(r *http.Request, sec *worldpack.KubeSecret, ns string) map[string]any {
	data := map[string]any{}
	for key, val := range sec.Data {
		rendered := s.renderCanaries(r, val, "kube", map[string]any{"namespace": ns, "secret": sec.Name, "key": key})
		data[key] = base64.StdEncoding.EncodeToString([]byte(rendered))
	}
	return map[string]any{"kind": "Secret", "apiVersion": "v1", "metadata": kubeMeta(sec.Name, ns),
		"data": data, "type": defaultStr(sec.Type, "Opaque")}
}

func (s *Server) configMapObj(r *http.Request, c worldpack.KubeConfigMap, ns string) map[string]any {
	data := map[string]any{}
	for key, val := range c.Data {
		data[key] = s.renderCanaries(r, val, "kube", map[string]any{"namespace": ns, "configmap": c.Name, "key": key})
	}
	return map[string]any{"kind": "ConfigMap", "apiVersion": "v1", "metadata": kubeMeta(c.Name, ns), "data": data}
}

func deployObj(d worldpack.KubeDeployment, ns string) map[string]any {
	return map[string]any{"kind": "Deployment", "apiVersion": "apps/v1", "metadata": kubeMeta(d.Name, ns),
		"spec": map[string]any{"replicas": d.Replicas, "selector": map[string]any{"matchLabels": map[string]any{"app": d.Name}},
			"template": map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": d.Name, "image": d.Image}}}}},
		"status": map[string]any{"replicas": d.Replicas, "readyReplicas": d.Replicas, "availableReplicas": d.Replicas}}
}

func nodeObj(n worldpack.KubeNode) map[string]any {
	gpu := fmt.Sprint(n.GPU)
	capacity := map[string]any{"cpu": "96", "memory": "1177424Mi", "pods": "250", "ephemeral-storage": "1000Gi"}
	if n.GPU > 0 {
		capacity["nvidia.com/gpu"] = gpu
	}
	labels := map[string]any{"kubernetes.io/hostname": n.Name, "node.kubernetes.io/instance-type": n.InstanceType,
		"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}
	if n.GPU > 0 {
		labels["nvidia.com/gpu.present"] = "true"
	}
	return map[string]any{"kind": "Node", "apiVersion": "v1",
		"metadata": map[string]any{"name": n.Name, "uid": uuidV4(), "labels": labels, "creationTimestamp": kubeClusterBorn},
		"spec":     map[string]any{"providerID": n.ProviderID},
		"status": map[string]any{"capacity": capacity, "allocatable": capacity,
			"addresses":  []any{map[string]any{"type": "InternalIP", "address": n.InternalIP}, map[string]any{"type": "Hostname", "address": n.Name}},
			"nodeInfo":   map[string]any{"kubeletVersion": n.KubeletVersion, "osImage": "Amazon Linux 2", "containerRuntimeVersion": "containerd://1.7.11", "architecture": "amd64", "operatingSystem": "linux"},
			"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}}}
}

func nsObj(name string) map[string]any {
	return map[string]any{"kind": "Namespace", "apiVersion": "v1",
		"metadata": map[string]any{"name": name, "uid": uuidV4(), "creationTimestamp": kubeClusterBorn},
		"status":   map[string]any{"phase": "Active"}}
}

func kubeMeta(name, ns string) map[string]any {
	return map[string]any{"name": name, "namespace": ns, "uid": uuidV4(),
		"resourceVersion": "48213", "creationTimestamp": kubeClusterBorn}
}

func listObj(kind string, items []any) map[string]any {
	if items == nil {
		items = []any{}
	}
	return map[string]any{"kind": kind, "apiVersion": "v1",
		"metadata": map[string]any{"resourceVersion": "48231"}, "items": items}
}

func appsListObj(kind string, items []any) map[string]any {
	o := listObj(kind, items)
	o["apiVersion"] = "apps/v1"
	return o
}

func (s *Server) noteKube(r *http.Request, verb, resource, ns, name string) {
	d := map[string]any{"op": "kube_" + verb, "resource": resource}
	if ns != "" {
		d["namespace"] = ns
	}
	if name != "" {
		d["name"] = truncate(name, 200)
	}
	s.emit(r, events.Event{Kind: events.KindToolCall, Detail: d})
}

// kubeStatus writes a Kubernetes Status error object.
func (s *Server) kubeStatus(w http.ResponseWriter, r *http.Request, code int, reason, message, ns string) {
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	writeKubeJSON(w, code, map[string]any{"kind": "Status", "apiVersion": "v1", "metadata": map[string]any{},
		"status": "Failure", "message": message, "reason": reason, "code": code})
}

func writeKubeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// containerName strips a pod's generated suffix for a plausible container name.
func containerName(pod string) string {
	parts := strings.Split(pod, "-")
	if len(parts) > 2 {
		return strings.Join(parts[:len(parts)-2], "-")
	}
	return pod
}

func kubeMajorMinor(v string) (string, string) {
	v = strings.TrimPrefix(v, "v")
	f := strings.SplitN(v, ".", 3)
	if len(f) < 2 {
		return "1", "30"
	}
	return f[0], f[1]
}

const kubeClusterBorn = "2026-01-20T12:00:00Z"
