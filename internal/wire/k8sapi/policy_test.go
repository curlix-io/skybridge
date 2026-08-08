package k8sapi

import (
	"net/http"
	"testing"
)

func TestClassifyAllowsReads(t *testing.T) {
	cases := []struct {
		method, path string
	}{
		{http.MethodGet, "/api/v1/namespaces/default/pods"},
		{http.MethodGet, "/api/v1/namespaces/default/pods/my-pod"},
		{http.MethodGet, "/apis/apps/v1/namespaces/default/deployments"},
		{http.MethodGet, "/api/v1/namespaces/default/pods/my-pod/log"},
	}
	for _, c := range cases {
		d := Classify(c.method, c.path)
		if d.Blocked {
			t.Errorf("%s %s: expected allowed, got blocked (%s)", c.method, c.path, d.Reason)
		}
		if !d.ReadOnly {
			t.Errorf("%s %s: expected read-only classification", c.method, c.path)
		}
	}
}

func TestClassifyBlocksInteractiveSubresources(t *testing.T) {
	cases := []string{
		"/api/v1/namespaces/default/pods/my-pod/exec",
		"/api/v1/namespaces/default/pods/my-pod/attach",
		"/api/v1/namespaces/default/pods/my-pod/portforward",
	}
	for _, path := range cases {
		if d := Classify(http.MethodPost, path); !d.Blocked {
			t.Errorf("%s: expected blocked", path)
		}
	}
}

func TestClassifyBlocksClusterWideDelete(t *testing.T) {
	cases := []string{
		"/api/v1/namespaces",
		"/apis/apiextensions.k8s.io/v1/customresourcedefinitions",
		"/api/v1/nodes",
	}
	for _, path := range cases {
		if d := Classify(http.MethodDelete, path); !d.Blocked {
			t.Errorf("DELETE %s: expected blocked (cluster-wide)", path)
		}
	}
}

func TestClassifyAllowsScopedDelete(t *testing.T) {
	d := Classify(http.MethodDelete, "/api/v1/namespaces/default/pods/my-pod")
	if d.Blocked {
		t.Fatalf("expected scoped pod delete to be allowed, got reason=%q", d.Reason)
	}
	if d.ReadOnly {
		t.Error("delete should not be classified read-only")
	}
	if d.Resource != "pods" {
		t.Errorf("expected resource=pods, got %q", d.Resource)
	}
}

func TestClassifyWriteMethods(t *testing.T) {
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		d := Classify(m, "/api/v1/namespaces/default/pods/my-pod")
		if d.ReadOnly {
			t.Errorf("%s: expected write classification", m)
		}
	}
}

func TestIsUpgradeRequest(t *testing.T) {
	h := http.Header{}
	if IsUpgradeRequest(h) {
		t.Error("expected no upgrade for empty headers")
	}
	h.Set("Upgrade", "SPDY/3.1")
	if !IsUpgradeRequest(h) {
		t.Error("expected upgrade detected via Upgrade header")
	}
	h2 := http.Header{}
	h2.Set("Connection", "Upgrade")
	if !IsUpgradeRequest(h2) {
		t.Error("expected upgrade detected via Connection header")
	}
}
