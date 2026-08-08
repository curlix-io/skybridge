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
	k, err := parseEdgeKey("curlix://org-1:tok-abc@gw.curlix.io?edge_id=edge-1&region=us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := EdgeKey{OrgID: "org-1", EnrollmentToken: "tok-abc", GatewayHost: "gw.curlix.io", EdgeID: "edge-1", AWSRegion: "us-east-1"}
	if !reflect.DeepEqual(k, want) {
		t.Fatalf("got %+v, want %+v", k, want)
	}
}

func TestParseEdgeKeyWithCABundle(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(pem))
	k, err := parseEdgeKey("curlix://org-1:tok-abc@gw.curlix.io?ca=" + encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(k.CABundlePEM) != pem {
		t.Fatalf("expected CA bundle %q, got %q", pem, string(k.CABundlePEM))
	}
}

func TestParseEdgeKeyWithoutCABundleLeavesItEmpty(t *testing.T) {
	k, err := parseEdgeKey("curlix://org-1:tok-abc@gw.curlix.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(k.CABundlePEM) != 0 {
		t.Fatalf("expected empty CA bundle, got %q", string(k.CABundlePEM))
	}
}

func TestParseEdgeKeyMalformedCABundleErrors(t *testing.T) {
	if _, err := parseEdgeKey("curlix://org-1:tok-abc@gw.curlix.io?ca=not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for malformed ca parameter")
	}
}

func TestParseEdgeKeyMinimal(t *testing.T) {
	k, err := parseEdgeKey("curlix://org-1:tok-abc@gw.curlix.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.OrgID != "org-1" || k.EnrollmentToken != "tok-abc" || k.GatewayHost != "gw.curlix.io" {
		t.Fatalf("unexpected result: %+v", k)
	}
	if k.EdgeID != "" || k.AWSRegion != "" {
		t.Fatalf("expected optional fields empty, got %+v", k)
	}
}

func TestParseEdgeKeyWrongSchemeErrors(t *testing.T) {
	if _, err := parseEdgeKey("grpcs://org-1:tok@gw.curlix.io"); err == nil {
		t.Fatal("expected error for non-curlix scheme")
	}
}

func TestParseEdgeKeyMissingHostErrors(t *testing.T) {
	if _, err := parseEdgeKey("curlix://org-1:tok@"); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestParseEdgeKeyMissingOrgIDErrors(t *testing.T) {
	if _, err := parseEdgeKey("curlix://gw.curlix.io"); err == nil {
		t.Fatal("expected error for missing org id")
	}
}

func TestParseEdgeKeyMalformedURLErrors(t *testing.T) {
	if _, err := parseEdgeKey("curlix://%zz"); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

func TestHostPortEmptyHost(t *testing.T) {
	if got := hostPort("", "7100"); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestHostPortAppendsPort(t *testing.T) {
	if got := hostPort("gw.curlix.io", "7100"); got != "gw.curlix.io:7100" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadEdgeFromSkybridgeKey(t *testing.T) {
	t.Setenv("SKYBRIDGE_KEY", "curlix://org-1:tok-abc@gw.curlix.io?edge_id=edge-1&region=us-east-1")
	e := LoadEdge()
	if e.GatewayAddr != "gw.curlix.io:7100" {
		t.Fatalf("expected GatewayAddr from key, got %q", e.GatewayAddr)
	}
	if e.EnrollTarget != "gw.curlix.io:7101" {
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
	t.Setenv("SKYBRIDGE_KEY", "curlix://org-1:tok-abc@gw.curlix.io")
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

func TestLoadEdgeCABundleFromSkybridgeKey(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(pem))
	t.Setenv("SKYBRIDGE_KEY", "curlix://org-1:tok-abc@gw.curlix.io?ca="+encoded)
	e := LoadEdge()
	if string(e.CABundle) != pem {
		t.Fatalf("expected CABundle from key, got %q", string(e.CABundle))
	}
}

func TestLoadEdgeDiscreteCABundleOverridesSkybridgeKey(t *testing.T) {
	pem := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(pem))
	t.Setenv("SKYBRIDGE_KEY", "curlix://org-1:tok-abc@gw.curlix.io?ca="+encoded)
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
