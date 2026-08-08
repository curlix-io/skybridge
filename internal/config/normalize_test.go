package config

import "testing"

func TestSwapGatewayPort(t *testing.T) {
	cases := []struct {
		addr, from, to, want string
	}{
		{"", "7100", "7200", ""},
		{"gw.internal:7100", "7100", "7200", "gw.internal:7200"},
		{"gw.internal:9999", "7100", "7200", "gw.internal:9999"},
		{"gw.internal", "7100", "7200", "gw.internal:7200"},
	}
	for _, c := range cases {
		if got := swapGatewayPort(c.addr, c.from, c.to); got != c.want {
			t.Errorf("swapGatewayPort(%q, %q, %q) = %q, want %q", c.addr, c.from, c.to, got, c.want)
		}
	}
}

func TestNormalizeEdgeNilIsNoop(t *testing.T) {
	NormalizeEdge(nil) // must not panic
}

func TestNormalizeEdgeSkipsWhenStudioNotWanted(t *testing.T) {
	e := &Edge{GatewayAddr: "gw:7100"}
	NormalizeEdge(e)
	if e.StudioGateway != "" {
		t.Fatalf("expected StudioGateway to remain empty when no studio signal is present, got %q", e.StudioGateway)
	}
}

func TestNormalizeEdgeSkipsWhenAutoDisabled(t *testing.T) {
	t.Setenv("SKYBRIDGE_STUDIO_AUTO", "0")
	e := &Edge{GatewayAddr: "gw:7100", StudioTargetsJSON: `[{"name":"x"}]`}
	NormalizeEdge(e)
	if e.StudioGateway != "" {
		t.Fatalf("expected StudioGateway untouched when SKYBRIDGE_STUDIO_AUTO=0, got %q", e.StudioGateway)
	}
}

func TestNormalizeEdgeDerivesStudioGatewayFromGatewayAddr(t *testing.T) {
	e := &Edge{GatewayAddr: "gw.internal:7100", StudioTargetsJSON: `[{"name":"x"}]`}
	NormalizeEdge(e)
	if e.StudioGateway != "gw.internal:7200" {
		t.Fatalf("expected derived studio gateway, got %q", e.StudioGateway)
	}
}

func TestNormalizeEdgeDoesNotOverrideExplicitStudioGateway(t *testing.T) {
	e := &Edge{GatewayAddr: "gw.internal:7100", StudioGateway: "explicit:7200"}
	NormalizeEdge(e)
	if e.StudioGateway != "explicit:7200" {
		t.Fatalf("expected explicit StudioGateway to be preserved, got %q", e.StudioGateway)
	}
}

func TestNormalizeEdgeDerivesStudioEnrollGatewayFromEnrollTarget(t *testing.T) {
	e := &Edge{GatewayAddr: "gw:7100", EnrollTarget: "enroll.internal:7101", StudioGateway: "studio:7200"}
	NormalizeEdge(e)
	if e.StudioEnrollGateway != "enroll.internal:7201" {
		t.Fatalf("expected enroll gateway derived from EnrollTarget, got %q", e.StudioEnrollGateway)
	}
}

func TestNormalizeEdgeDerivesStudioEnrollGatewayFromGatewayAddrWhenNoEnrollTarget(t *testing.T) {
	e := &Edge{GatewayAddr: "gw.internal:7100", StudioGateway: "studio:7200"}
	NormalizeEdge(e)
	if e.StudioEnrollGateway != "gw.internal:7201" {
		t.Fatalf("expected enroll gateway derived from GatewayAddr, got %q", e.StudioEnrollGateway)
	}
}

func TestNormalizeEdgePropagatesEnrollTokenAndEdgeID(t *testing.T) {
	e := &Edge{GatewayAddr: "gw:7100", StudioGateway: "studio:7200", EnrollToken: "tok", EdgeID: "edge-1"}
	NormalizeEdge(e)
	if e.StudioEnrollmentToken != "tok" {
		t.Fatalf("expected StudioEnrollmentToken to fall back to EnrollToken, got %q", e.StudioEnrollmentToken)
	}
	if e.StudioAgentID != "edge-1" {
		t.Fatalf("expected StudioAgentID to fall back to EdgeID, got %q", e.StudioAgentID)
	}
}

func TestNormalizeEdgeDoesNotOverrideExplicitStudioFields(t *testing.T) {
	e := &Edge{
		GatewayAddr:           "gw:7100",
		StudioGateway:         "studio:7200",
		EnrollToken:           "tok",
		StudioEnrollmentToken: "explicit-token",
		EdgeID:                "edge-1",
		StudioAgentID:         "explicit-agent",
	}
	NormalizeEdge(e)
	if e.StudioEnrollmentToken != "explicit-token" || e.StudioAgentID != "explicit-agent" {
		t.Fatalf("expected explicit studio fields preserved, got token=%q agent=%q", e.StudioEnrollmentToken, e.StudioAgentID)
	}
}
