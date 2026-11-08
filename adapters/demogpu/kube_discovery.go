package demogpu

// Kubernetes API discovery documents (/apis, /api/v1, ...) and small id
// helpers. kubectl walks these before any resource request, so they must be
// present and well-formed for the facade to behave like a real cluster.

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func uuidV4() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func uuidHex() string {
	var b [20]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func kubeAPIGroupList() map[string]any {
	group := func(name, version string) map[string]any {
		gv := version
		if name != "" {
			gv = name + "/" + version
		}
		return map[string]any{"name": name,
			"versions":         []any{map[string]any{"groupVersion": gv, "version": version}},
			"preferredVersion": map[string]any{"groupVersion": gv, "version": version}}
	}
	return map[string]any{"kind": "APIGroupList", "apiVersion": "v1", "groups": []any{
		group("apps", "v1"),
		group("batch", "v1"),
		group("authorization.k8s.io", "v1"),
		group("rbac.authorization.k8s.io", "v1"),
		group("apiextensions.k8s.io", "v1"),
	}}
}

func resource(name, kind string, namespaced bool, verbs ...string) map[string]any {
	if len(verbs) == 0 {
		verbs = []string{"get", "list", "watch"}
	}
	return map[string]any{"name": name, "singularName": "", "namespaced": namespaced, "kind": kind, "verbs": verbs}
}

func kubeCoreResources() map[string]any {
	return map[string]any{"kind": "APIResourceList", "groupVersion": "v1", "resources": []any{
		resource("namespaces", "Namespace", false),
		resource("nodes", "Node", false),
		resource("pods", "Pod", true),
		resource("services", "Service", true),
		resource("secrets", "Secret", true),
		resource("configmaps", "ConfigMap", true),
		resource("serviceaccounts", "ServiceAccount", true),
		resource("events", "Event", true),
	}}
}

func kubeAppsResources() map[string]any {
	return map[string]any{"kind": "APIResourceList", "groupVersion": "apps/v1", "resources": []any{
		resource("deployments", "Deployment", true),
		resource("replicasets", "ReplicaSet", true),
		resource("statefulsets", "StatefulSet", true),
		resource("daemonsets", "DaemonSet", true),
	}}
}

func kubeAuthzResources() map[string]any {
	return map[string]any{"kind": "APIResourceList", "groupVersion": "authorization.k8s.io/v1", "resources": []any{
		resource("selfsubjectaccessreviews", "SelfSubjectAccessReview", false, "create"),
		resource("selfsubjectrulesreviews", "SelfSubjectRulesReview", false, "create"),
		resource("subjectaccessreviews", "SubjectAccessReview", false, "create"),
	}}
}
