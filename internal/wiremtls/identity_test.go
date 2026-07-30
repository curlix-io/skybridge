package wiremtls

import "testing"

func TestSpiffeIDRoundTrip(t *testing.T) {
	uri := SpiffeID("", "org-1", "agent-a")
	tenant, agentID, ok := ParseSpiffeID(uri)
	if !ok {
		t.Fatalf("ParseSpiffeID(%q) failed to parse", uri)
	}
	if tenant != "org-1" || agentID != "agent-a" {
		t.Fatalf("got tenant=%q agent=%q, want org-1/agent-a", tenant, agentID)
	}
}

func TestParseSpiffeIDRejectsWrongShape(t *testing.T) {
	cases := []string{
		"",
		"not-a-uri",
		"spiffe://curlix.connector/tenant/org-1/connector/c1", // different fleet's shape
		"spiffe://curlix.wire-agent/tenant//agent/a1",         // empty tenant
		"spiffe://curlix.wire-agent/tenant/org-1/agent/",      // empty agent
	}
	for _, c := range cases {
		if _, _, ok := ParseSpiffeID(c); ok {
			t.Errorf("ParseSpiffeID(%q) should not parse", c)
		}
	}
}

func TestGenerateKeyAndCSRCarriesSpiffeSAN(t *testing.T) {
	_, csrPEM, err := GenerateKeyAndCSR("", "org-1", "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(csrPEM) == 0 {
		t.Fatal("expected non-empty CSR PEM")
	}
}
