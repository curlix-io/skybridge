package config

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestParseEdgeKeyEmptyReturnsZeroValue(t *testing.T) {
	k, err := parseEdgeKey("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(k, EdgeKey{}) {
		t.Fatalf("expected zero value, got %+v", k)
	}
}

func TestParseEdgeKeyFull(t *testing.T) {
	k, err := parseEdgeKey("skybridge://org-1:tok-abc@gw.example.com?edge_id=edge-1&region=us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := EdgeKey{OrgID: "org-1", EnrollmentToken: "tok-abc", GatewayHost: "gw.example.com", EdgeID: "edge-1", AWSRegion: "us-east-1"}
	if !reflect.DeepEqual(k, want) {
		t.Fatalf("got %+v, want %+v", k, want)
	}
}

func TestParseEdgeKeyWithCABundle(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(pem))
	k, err := parseEdgeKey("skybridge://org-1:tok-abc@gw.example.com?ca=" + encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(k.CABundlePEM) != pem {
		t.Fatalf("expected CA bundle %q, got %q", pem, string(k.CABundlePEM))
	}
}

func TestParseEdgeKeyWithoutCABundleLeavesItEmpty(t *testing.T) {
	k, err := parseEdgeKey("skybridge://org-1:tok-abc@gw.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(k.CABundlePEM) != 0 {
		t.Fatalf("expected empty CA bundle, got %q", string(k.CABundlePEM))
	}
}

func TestParseEdgeKeyMalformedCABundleErrors(t *testing.T) {
	if _, err := parseEdgeKey("skybridge://org-1:tok-abc@gw.example.com?ca=not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for malformed ca parameter")
	}
}

func TestParseEdgeKeyMinimal(t *testing.T) {
	k, err := parseEdgeKey("skybridge://org-1:tok-abc@gw.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.OrgID != "org-1" || k.EnrollmentToken != "tok-abc" || k.GatewayHost != "gw.example.com" {
		t.Fatalf("unexpected result: %+v", k)
	}
	if k.EdgeID != "" || k.AWSRegion != "" {
		t.Fatalf("expected optional fields empty, got %+v", k)
	}
}

func TestParseEdgeKeyWrongSchemeErrors(t *testing.T) {
	if _, err := parseEdgeKey("grpcs://org-1:tok@gw.example.com"); err == nil {
		t.Fatal("expected error for wrong scheme")
	}
}

func TestParseEdgeKeyMissingHostErrors(t *testing.T) {
	if _, err := parseEdgeKey("skybridge://org-1:tok@"); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestParseEdgeKeyMissingOrgIDErrors(t *testing.T) {
	if _, err := parseEdgeKey("skybridge://gw.example.com"); err == nil {
		t.Fatal("expected error for missing org id")
	}
}

func TestParseEdgeKeyMalformedURLErrors(t *testing.T) {
	if _, err := parseEdgeKey("skybridge://%zz"); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestHostPortEmptyHost(t *testing.T) {
	if got := hostPort("", "7100"); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestHostPortAppendsPort(t *testing.T) {
	if got := hostPort("gw.example.com", "7100"); got != "gw.example.com:7100" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadEdgeFromSkybridgeKey(t *testing.T) {
	t.Setenv("SKYBRIDGE_KEY", "skybridge://org-1:tok-abc@gw.example.com?edge_id=edge-1&region=us-east-1")
	e := LoadEdge()
	if e.GatewayAddr != "gw.example.com:7100" {
		t.Fatalf("expected GatewayAddr from key, got %q", e.GatewayAddr)
	}
	if e.EnrollTarget != "gw.example.com:7101" {
		t.Fatalf("expected EnrollTarget from key, got %q", e.EnrollTarget)
	}
	if e.TenantID != "org-1" {
		t.Fatalf("expected TenantID from key, got %q", e.TenantID)
	}
	if e.EdgeID != "edge-1" {
		t.Fatalf("expected EdgeID from key, got %q", e.EdgeID)
	}
	if e.Token != "tok-abc" {
		t.Fatalf("expected Token from key, got %q", e.Token)
	}
	if e.EnrollToken != "tok-abc" {
		t.Fatalf("expected EnrollToken from key, got %q", e.EnrollToken)
	}
	if e.AWSRegion != "us-east-1" {
		t.Fatalf("expected AWSRegion from key, got %q", e.AWSRegion)
	}
}

func TestLoadEdgeDiscreteVarsOverrideSkybridgeKey(t *testing.T) {
	t.Setenv("SKYBRIDGE_KEY", "skybridge://org-1:tok-abc@gw.example.com")
	t.Setenv("SKYBRIDGE_ORG_ID", "org-explicit")
	t.Setenv("SKYBRIDGE_EDGE_GATEWAY", "explicit-gw:9999")
	e := LoadEdge()
	if e.TenantID != "org-explicit" {
		t.Fatalf("expected explicit SKYBRIDGE_ORG_ID to win, got %q", e.TenantID)
	}
	if e.GatewayAddr != "explicit-gw:9999" {
		t.Fatalf("expected explicit SKYBRIDGE_EDGE_GATEWAY to win, got %q", e.GatewayAddr)
	}
}

// SKYBRIDGE_GATEWAY is also LoadAgent's own env var for the *wire proxy's* target. A deployment
// with both SKYBRIDGE_KEY (this edge's call-home target) and a co-located wire proxy
// (SKYBRIDGE_GATEWAY pointed at a distinct wire NLB) must not have the wire proxy's address
// silently win here — the edge would dial the wrong host and fail TLS verification against the
// connector CA. Regression for a real bug: before this fix, GatewayAddr's fallback chain checked
// SKYBRIDGE_GATEWAY before the key-derived host, so this exact combination broke call-home.
func TestLoadEdgeSkybridgeKeyWinsOverSharedWireProxyGatewayVar(t *testing.T) {
	t.Setenv("SKYBRIDGE_KEY", "skybridge://org-1:tok-abc@gw.example.com")
	t.Setenv("SKYBRIDGE_GATEWAY", "wire.example.com:8010")
	e := LoadEdge()
	if e.GatewayAddr != "gw.example.com:7100" {
		t.Fatalf("expected key-derived GatewayAddr to win over shared SKYBRIDGE_GATEWAY, got %q", e.GatewayAddr)
	}
	if e.WireProxy.GatewayAddr != "wire.example.com:8010" {
		t.Fatalf("expected wire proxy's own GatewayAddr from SKYBRIDGE_GATEWAY, got %q", e.WireProxy.GatewayAddr)
	}
}

func TestLoadEdgeCABundleFromSkybridgeKey(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(pem))
	t.Setenv("SKYBRIDGE_KEY", "skybridge://org-1:tok-abc@gw.example.com?ca="+encoded)
	e := LoadEdge()
	if string(e.CABundle) != pem {
		t.Fatalf("expected CABundle from key, got %q", string(e.CABundle))
	}
}

func TestLoadEdgeDiscreteCABundleOverridesSkybridgeKey(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(pem))
	t.Setenv("SKYBRIDGE_KEY", "skybridge://org-1:tok-abc@gw.example.com?ca="+encoded)
	t.Setenv("SKYBRIDGE_CA_BUNDLE_PEM", "explicit-pem")
	e := LoadEdge()
	if string(e.CABundle) != "explicit-pem" {
		t.Fatalf("expected explicit SKYBRIDGE_CA_BUNDLE_PEM to win, got %q", string(e.CABundle))
	}
}

func TestLoadEdgeInvalidSkybridgeKeyIgnoredNotFatal(t *testing.T) {
	t.Setenv("SKYBRIDGE_KEY", "not-a-valid-dsn")
	e := LoadEdge()
	if e.GatewayAddr != "" || e.TenantID != "" {
		t.Fatalf("expected empty edge config on invalid key, got %+v", e)
	}
}
