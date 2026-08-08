// Package k8sapi implements the Kubernetes API server's HTTPS/REST surface as a masking proxy
// engine, mirroring the shape of internal/wire/postgres|mysql|mongo (client connects to the agent;
// the agent dials the real upstream — here, the cluster API server — and masks server->client
// payloads before they leave the customer network). Structurally different from those engines only
// in transport: HTTP/1.1 request/response over TLS instead of a binary wire protocol, so this
// engine terminates HTTP itself rather than a length-prefixed frame format.
//
// Scope: structured API calls only (get/describe/logs/apply/delete/patch/...) — see
// docs/design/kubernetes-access-broker.md §2. Interactive subresources (exec/attach/port-forward)
// and any connection-upgrade request are rejected outright: there is no structured request/response
// to mask once the connection stops speaking HTTP, the same posture RDP session brokering (a
// bidirectional byte stream) has left unsolved.
package k8sapi

import (
	"net/http"
	"strings"
)

// interactiveSubresources are Kubernetes API subresources that upgrade to a bidirectional stream
// (SPDY/WebSocket) rather than making one structured request/response — never brokered. "cp" has no
// dedicated API subresource; it is implemented client-side on top of "exec", which is already
// blocked.
var interactiveSubresources = map[string]bool{
	"exec":        true,
	"attach":      true,
	"portforward": true,
}

// blockedDeleteTargets mirrors internal/edge/k8sexec/policy.go's cluster-wide-delete blocklist,
// re-expressed against the API resource plural in the URL path instead of a kubectl CLI argument.
var blockedDeleteTargets = map[string]bool{
	"namespaces":                true,
	"customresourcedefinitions": true,
	"nodes":                     true,
}

// writeMethods are HTTP methods that mutate cluster state.
var writeMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// Decision is the outcome of classifying one proxied request.
type Decision struct {
	ReadOnly bool
	Blocked  bool
	Reason   string
	// Resource is the parsed API resource plural (e.g. "pods", "deployments"), when known.
	Resource string
}

// Classify decides whether to allow, and how to classify (read-only vs write), one incoming
// Kubernetes API request. path is the request URL path (e.g. "/api/v1/namespaces/default/pods").
func Classify(method, path string) Decision {
	if isUpgradeSubresource(path) {
		return Decision{Blocked: true, Reason: "interactive subresource not brokered: " + lastSubresource(path)}
	}

	resource, name := parseResourceAndName(path)
	readOnly := !writeMethods[strings.ToUpper(method)]

	if strings.EqualFold(method, http.MethodDelete) && name == "" && blockedDeleteTargets[resource] {
		return Decision{Blocked: true, Reason: "cluster-wide delete not allowed: " + resource, Resource: resource}
	}

	return Decision{ReadOnly: readOnly, Resource: resource}
}

// IsUpgradeRequest reports whether h asks to upgrade the HTTP connection (SPDY/WebSocket) — the
// transport interactive kubectl exec/attach/port-forward use. Even if a future path-based check
// were bypassed, an upgrade request is rejected outright: there is no structured request/response
// to mask or classify once the connection stops speaking HTTP.
func IsUpgradeRequest(h http.Header) bool {
	if strings.TrimSpace(h.Get("Upgrade")) != "" {
		return true
	}
	return strings.Contains(strings.ToLower(h.Get("Connection")), "upgrade")
}

func isUpgradeSubresource(path string) bool {
	return interactiveSubresources[lastSubresource(path)]
}

// lastSubresource returns the final path segment when it names a known subresource verb
// (".../pods/{name}/exec" -> "exec"); empty otherwise.
func lastSubresource(path string) string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return ""
	}
	segs := strings.Split(trimmed, "/")
	return segs[len(segs)-1]
}

// parseResourceAndName extracts (resource, name) from a Kubernetes API path. Handles both
// core (/api/v1/...) and grouped (/apis/{group}/{version}/...) forms, each optionally namespaced:
//
//	/api/v1/namespaces/{ns}/{resource}[/{name}[/{subresource}]]
//	/api/v1/{resource}[/{name}]
//	/apis/{group}/{version}/namespaces/{ns}/{resource}[/{name}]
//	/apis/{group}/{version}/{resource}[/{name}]
func parseResourceAndName(path string) (resource, name string) {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	var rest []string
	switch {
	case len(segs) >= 2 && segs[0] == "api":
		rest = segs[2:] // skip "api", version
	case len(segs) >= 3 && segs[0] == "apis":
		rest = segs[3:] // skip "apis", group, version
	default:
		return "", ""
	}
	if len(rest) >= 2 && rest[0] == "namespaces" {
		rest = rest[2:] // skip "namespaces", {ns}
	}
	if len(rest) >= 1 {
		resource = rest[0]
	}
	if len(rest) >= 2 {
		name = rest[1]
	}
	return resource, name
}
