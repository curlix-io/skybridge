package studiotransport

import "testing"

func TestSpiffeIDDefaults(t *testing.T) {
	got := spiffeID("", "org-1", "")
	want := "spiffe://curlix.studio-agent/tenant/org-1/agent/studio-agent"
	if got != want {
		t.Fatalf("spiffeID() = %q, want %q", got, want)
	}
}

func TestSpiffeIDExplicitTrustDomainAndAgent(t *testing.T) {
	got := spiffeID("custom.domain", "org-1", "agent-a")
	want := "spiffe://custom.domain/tenant/org-1/agent/agent-a"
	if got != want {
		t.Fatalf("spiffeID() = %q, want %q", got, want)
	}
}

func TestParseSPIFFERoundTrip(t *testing.T) {
	uri := spiffeID("", "org-1", "agent-a")
	tenant, agent, ok := parseSPIFFE(uri)
	if !ok || tenant != "org-1" || agent != "agent-a" {
		t.Fatalf("parseSPIFFE(%q) = %q, %q, %v", uri, tenant, agent, ok)
	}
}

func TestParseSPIFFERejectsWrongTrustDomain(t *testing.T) {
	if _, _, ok := parseSPIFFE("spiffe://other.domain/tenant/org-1/agent/agent-a"); ok {
		t.Fatal("expected rejection for a different trust domain")
	}
}

func TestParseSPIFFERejectsMissingAgentMarker(t *testing.T) {
	if _, _, ok := parseSPIFFE("spiffe://curlix.studio-agent/tenant/org-1"); ok {
		t.Fatal("expected rejection when /agent/ marker is missing")
	}
}

func TestParseSPIFFERejectsEmptyTenantOrAgent(t *testing.T) {
	cases := []string{
		"spiffe://curlix.studio-agent/tenant//agent/a1",
		"spiffe://curlix.studio-agent/tenant/org-1/agent/",
	}
	for _, c := range cases {
		if _, _, ok := parseSPIFFE(c); ok {
			t.Errorf("parseSPIFFE(%q) should not parse", c)
		}
	}
}

func TestSpiffeURIParsed(t *testing.T) {
	u, err := spiffeURIParsed("", "org-1", "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "spiffe" {
		t.Fatalf("expected spiffe scheme, got %q", u.Scheme)
	}
}
