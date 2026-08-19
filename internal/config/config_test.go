package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAgentDefaults(t *testing.T) {
	a := LoadAgent()
	if a.Mode != ModeListener {
		t.Fatalf("expected default mode %q, got %q", ModeListener, a.Mode)
	}
	if a.DBType != "postgres" {
		t.Fatalf("expected default db type postgres, got %q", a.DBType)
	}
	if a.ListenAddr != ":15432" {
		t.Fatalf("expected default postgres listen addr, got %q", a.ListenAddr)
	}
	if a.MaskLanguage != "en" {
		t.Fatalf("expected default mask language en, got %q", a.MaskLanguage)
	}
	if a.PIIOverlayPollSeconds != 60 {
		t.Fatalf("expected default poll seconds 60, got %d", a.PIIOverlayPollSeconds)
	}
	if a.InjectCredentials || a.ClientTLSSelfSigned || a.WireMtlsIamAuthEnabled {
		t.Fatal("expected all boolean toggles to default false")
	}
}

func TestLoadAgentDefaultListenAddrByDBType(t *testing.T) {
	cases := map[string]string{"mysql": ":13306", "mongodb": ":27018", "mongo": ":27018", "postgres": ":15432", "unknown": ":15432"}
	for dbType, want := range cases {
		t.Setenv("SKYBRIDGE_DB_TYPE", dbType)
		a := LoadAgent()
		if a.ListenAddr != want {
			t.Errorf("db_type=%q: got listen addr %q, want %q", dbType, a.ListenAddr, want)
		}
	}
}

func TestLoadAgentExplicitListenOverridesDefault(t *testing.T) {
	t.Setenv("SKYBRIDGE_DB_TYPE", "mysql")
	t.Setenv("SKYBRIDGE_LISTEN", ":9999")
	a := LoadAgent()
	if a.ListenAddr != ":9999" {
		t.Fatalf("expected explicit listen addr to win, got %q", a.ListenAddr)
	}
}

func TestLoadAgentTokenDefaultsPropagateToDerivedTokens(t *testing.T) {
	t.Setenv("SKYBRIDGE_TOKEN", "shared-token")
	a := LoadAgent()
	if a.PIIOverlayToken != "shared-token" {
		t.Fatalf("expected PIIOverlayToken to default to SKYBRIDGE_TOKEN, got %q", a.PIIOverlayToken)
	}
	if a.CredentialExchangeToken != "shared-token" {
		t.Fatalf("expected CredentialExchangeToken to default to SKYBRIDGE_TOKEN, got %q", a.CredentialExchangeToken)
	}
}

func TestLoadAgentDerivedTokensCanBeOverridden(t *testing.T) {
	t.Setenv("SKYBRIDGE_TOKEN", "shared-token")
	t.Setenv("SKYBRIDGE_PII_OVERLAY_TOKEN", "overlay-token")
	t.Setenv("SKYBRIDGE_CREDENTIAL_EXCHANGE_TOKEN", "exchange-token")
	a := LoadAgent()
	if a.PIIOverlayToken != "overlay-token" || a.CredentialExchangeToken != "exchange-token" {
		t.Fatalf("expected explicit overrides to win, got overlay=%q exchange=%q", a.PIIOverlayToken, a.CredentialExchangeToken)
	}
}

func TestLoadAgentPollSecondsInvalidFallsBackToDefault(t *testing.T) {
	t.Setenv("SKYBRIDGE_PII_OVERLAY_POLL_SECONDS", "not-a-number")
	a := LoadAgent()
	if a.PIIOverlayPollSeconds != 60 {
		t.Fatalf("expected fallback to default 60 on invalid input, got %d", a.PIIOverlayPollSeconds)
	}
}

func TestLoadAgentPollSecondsNegativeMeansFetchOnce(t *testing.T) {
	t.Setenv("SKYBRIDGE_PII_OVERLAY_POLL_SECONDS", "-1")
	a := LoadAgent()
	if a.PIIOverlayPollSeconds != -1 {
		t.Fatalf("expected -1 to pass through, got %d", a.PIIOverlayPollSeconds)
	}
}

func TestLoadAgentParsesTargetsJSON(t *testing.T) {
	t.Setenv("SKYBRIDGE_TARGETS", `[{"name":"prod","addr":"db:5432","db_type":"POSTGRES"}]`)
	a := LoadAgent()
	if len(a.Targets) != 1 {
		t.Fatalf("expected one target, got %d", len(a.Targets))
	}
	if a.Targets[0].DBType != "postgres" {
		t.Fatalf("expected db_type to be lowercased, got %q", a.Targets[0].DBType)
	}
	target, ok := a.TargetByName("prod")
	if !ok || target.Addr != "db:5432" {
		t.Fatalf("TargetByName(prod) = %v, %v", target, ok)
	}
	if _, ok := a.TargetByName("missing"); ok {
		t.Fatal("expected TargetByName to report false for an unknown name")
	}
}

func TestLoadAgentTargetsInvalidJSONReturnsNil(t *testing.T) {
	t.Setenv("SKYBRIDGE_TARGETS", `not json`)
	a := LoadAgent()
	if a.Targets != nil {
		t.Fatalf("expected nil targets on invalid JSON, got %v", a.Targets)
	}
}

func TestLoadAgentParsesPIIOverlayJSON(t *testing.T) {
	t.Setenv("SKYBRIDGE_PII_OVERLAY", `{"email":"[EMAIL]"}`)
	a := LoadAgent()
	if a.PIIOverlay["email"].Token != "[EMAIL]" {
		t.Fatalf("unexpected overlay: %v", a.PIIOverlay)
	}
}

func TestLoadAgentPIIOverlayInlineJSONNeverPartial(t *testing.T) {
	// The inline env var only ever supports a plain string (full-value replacement); a mapping
	// value there isn't a valid string, so json.Unmarshal into map[string]string fails and the
	// whole overlay comes back nil, per parseOverlay's contract.
	t.Setenv("SKYBRIDGE_PII_OVERLAY", `{"credit_card":{"partial_mask":true}}`)
	a := LoadAgent()
	if a.PIIOverlay != nil {
		t.Fatalf("expected nil overlay for a non-string inline value, got %v", a.PIIOverlay)
	}
}

func TestLoadAgentPIIOverlayInvalidJSONReturnsNil(t *testing.T) {
	t.Setenv("SKYBRIDGE_PII_OVERLAY", `not json`)
	a := LoadAgent()
	if a.PIIOverlay != nil {
		t.Fatalf("expected nil overlay on invalid JSON, got %v", a.PIIOverlay)
	}
}

func TestLoadAgentParsesPIIOverlayFileYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.yaml")
	yaml := "email: \"[EMAIL]\"\nssn: \"[SSN]\"\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKYBRIDGE_PII_OVERLAY_FILE", path)
	a := LoadAgent()
	if a.PIIOverlay["email"].Token != "[EMAIL]" || a.PIIOverlay["ssn"].Token != "[SSN]" {
		t.Fatalf("unexpected overlay: %v", a.PIIOverlay)
	}
}

func TestLoadAgentParsesPIIOverlayFilePartialMaskRule(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.yaml")
	yaml := "email: \"[EMAIL]\"\ncredit_card:\n  partial_mask: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKYBRIDGE_PII_OVERLAY_FILE", path)
	a := LoadAgent()
	if a.PIIOverlay["email"].Token != "[EMAIL]" || a.PIIOverlay["email"].Partial {
		t.Fatalf("expected email to be a plain token rule, got %+v", a.PIIOverlay["email"])
	}
	if !a.PIIOverlay["credit_card"].Partial {
		t.Fatalf("expected credit_card to be a partial-mask rule, got %+v", a.PIIOverlay["credit_card"])
	}
}

func TestLoadAgentPIIOverlayFileSkipsUnrecognizedRuleShapeButKeepsOthers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.yaml")
	yaml := "email: \"[EMAIL]\"\nbad_column:\n  something_else: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKYBRIDGE_PII_OVERLAY_FILE", path)
	a := LoadAgent()
	if a.PIIOverlay["email"].Token != "[EMAIL]" {
		t.Fatalf("expected valid rule to survive alongside a bad one, got %v", a.PIIOverlay)
	}
	if _, ok := a.PIIOverlay["bad_column"]; ok {
		t.Fatalf("expected unrecognized rule shape to be skipped, got %v", a.PIIOverlay["bad_column"])
	}
}

func TestLoadAgentPIIOverlayFileTakesPriorityOverInline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.yaml")
	if err := os.WriteFile(path, []byte("email: \"[FROM-FILE]\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKYBRIDGE_PII_OVERLAY_FILE", path)
	t.Setenv("SKYBRIDGE_PII_OVERLAY", `{"email":"[FROM-ENV]"}`)
	a := LoadAgent()
	if a.PIIOverlay["email"].Token != "[FROM-FILE]" {
		t.Fatalf("expected overlay file to take priority, got %v", a.PIIOverlay)
	}
}

func TestLoadAgentPIIOverlayFileMissingFallsBackToInline(t *testing.T) {
	t.Setenv("SKYBRIDGE_PII_OVERLAY_FILE", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("SKYBRIDGE_PII_OVERLAY", `{"email":"[FROM-ENV]"}`)
	a := LoadAgent()
	if a.PIIOverlay["email"].Token != "[FROM-ENV]" {
		t.Fatalf("expected fallback to inline overlay, got %v", a.PIIOverlay)
	}
}

func TestLoadAgentPIIOverlayFileInvalidYAMLFallsBackToInline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overlay.yaml")
	if err := os.WriteFile(path, []byte(":\n  - not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKYBRIDGE_PII_OVERLAY_FILE", path)
	t.Setenv("SKYBRIDGE_PII_OVERLAY", `{"email":"[FROM-ENV]"}`)
	a := LoadAgent()
	if a.PIIOverlay["email"].Token != "[FROM-ENV]" {
		t.Fatalf("expected fallback to inline overlay, got %v", a.PIIOverlay)
	}
}

func TestLoadAgentParsesMaskEntitiesCSV(t *testing.T) {
	t.Setenv("SKYBRIDGE_MASK_ENTITIES", " email_address ,US_SSN,,CREDIT_CARD")
	a := LoadAgent()
	want := []string{"EMAIL_ADDRESS", "US_SSN", "CREDIT_CARD"}
	if len(a.MaskEntities) != len(want) {
		t.Fatalf("unexpected entities: %v", a.MaskEntities)
	}
	for i, e := range want {
		if a.MaskEntities[i] != e {
			t.Fatalf("unexpected entities: %v", a.MaskEntities)
		}
	}
}

func TestLoadAgentMaskEntitiesEmptyReturnsNil(t *testing.T) {
	a := LoadAgent()
	if a.MaskEntities != nil {
		t.Fatalf("expected nil entities by default, got %v", a.MaskEntities)
	}
}

func TestLoadAgentParsesMaskAnonymizersJSON(t *testing.T) {
	t.Setenv("SKYBRIDGE_MASK_ANONYMIZERS", `{"US_SSN":{"type":"mask","masking_char":"*","chars_to_mask":5}}`)
	a := LoadAgent()
	ssn, ok := a.MaskAnonymizers["US_SSN"].(map[string]any)
	if !ok || ssn["type"] != "mask" {
		t.Fatalf("unexpected anonymizers: %v", a.MaskAnonymizers)
	}
}

func TestLoadAgentMaskAnonymizersInvalidJSONReturnsNil(t *testing.T) {
	t.Setenv("SKYBRIDGE_MASK_ANONYMIZERS", `not json`)
	a := LoadAgent()
	if a.MaskAnonymizers != nil {
		t.Fatalf("expected nil anonymizers on invalid JSON, got %v", a.MaskAnonymizers)
	}
}

func TestLoadAgentParsesMaskAllowListCSVPreservingCase(t *testing.T) {
	t.Setenv("SKYBRIDGE_MASK_ALLOW_LIST", " support@example.com ,555-0100,,Some-Value")
	a := LoadAgent()
	want := []string{"support@example.com", "555-0100", "Some-Value"}
	if len(a.MaskAllowList) != len(want) {
		t.Fatalf("unexpected allow list: %v", a.MaskAllowList)
	}
	for i, e := range want {
		if a.MaskAllowList[i] != e {
			t.Fatalf("unexpected allow list: %v", a.MaskAllowList)
		}
	}
}

func TestLoadAgentMaskAllowListEmptyReturnsNil(t *testing.T) {
	a := LoadAgent()
	if a.MaskAllowList != nil {
		t.Fatalf("expected nil allow list by default, got %v", a.MaskAllowList)
	}
}

func TestLoadAgentMaskAllowListMatchDefaultsToExact(t *testing.T) {
	a := LoadAgent()
	if a.MaskAllowListMatch != "exact" {
		t.Fatalf("expected default allow list match %q, got %q", "exact", a.MaskAllowListMatch)
	}
}

func TestLoadAgentMaskAllowListMatchHonorsRegex(t *testing.T) {
	t.Setenv("SKYBRIDGE_MASK_ALLOW_LIST_MATCH", "regex")
	a := LoadAgent()
	if a.MaskAllowListMatch != "regex" {
		t.Fatalf("expected allow list match %q, got %q", "regex", a.MaskAllowListMatch)
	}
}

func TestLoadAgentMaskModeDefaultsToBestEffort(t *testing.T) {
	a := LoadAgent()
	if a.MaskMode != ModeBestEffort {
		t.Fatalf("expected default mask mode %q, got %q", ModeBestEffort, a.MaskMode)
	}
	if a.MaskStrict() {
		t.Fatal("expected best-effort default to not be strict")
	}
}

func TestLoadAgentMaskModeStrict(t *testing.T) {
	t.Setenv("SKYBRIDGE_MASK_MODE", "STRICT")
	a := LoadAgent()
	if !a.MaskStrict() {
		t.Fatalf("expected strict mode (case-insensitive), got %q", a.MaskMode)
	}
}

func TestLoadAgentPEMFromInlineEnv(t *testing.T) {
	t.Setenv("SKYBRIDGE_CLIENT_TLS_CERT_PEM", "inline-cert-pem")
	a := LoadAgent()
	if string(a.ClientTLSCertPEM) != "inline-cert-pem" {
		t.Fatalf("expected inline PEM to be used, got %q", a.ClientTLSCertPEM)
	}
}

func TestLoadAgentPEMFromFileEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("file-cert-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKYBRIDGE_CLIENT_TLS_CERT_FILE", path)
	a := LoadAgent()
	if string(a.ClientTLSCertPEM) != "file-cert-pem" {
		t.Fatalf("expected file PEM to be used, got %q", a.ClientTLSCertPEM)
	}
}

func TestLoadAgentPEMInlineTakesPriorityOverFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, []byte("file-cert-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SKYBRIDGE_CLIENT_TLS_CERT_FILE", path)
	t.Setenv("SKYBRIDGE_CLIENT_TLS_CERT_PEM", "inline-cert-pem")
	a := LoadAgent()
	if string(a.ClientTLSCertPEM) != "inline-cert-pem" {
		t.Fatalf("expected inline PEM to take priority, got %q", a.ClientTLSCertPEM)
	}
}

func TestLoadAgentPEMFromMissingFileReturnsNil(t *testing.T) {
	t.Setenv("SKYBRIDGE_CLIENT_TLS_CERT_FILE", "/nonexistent/path/cert.pem")
	a := LoadAgent()
	if a.ClientTLSCertPEM != nil {
		t.Fatalf("expected nil PEM when file read fails, got %q", a.ClientTLSCertPEM)
	}
}

func TestClientTLSConfigured(t *testing.T) {
	cases := []struct {
		name string
		a    Agent
		want bool
	}{
		{"none", Agent{}, false},
		{"self-signed", Agent{ClientTLSSelfSigned: true}, true},
		{"cert-only", Agent{ClientTLSCertPEM: []byte("c")}, false},
		{"cert-and-key", Agent{ClientTLSCertPEM: []byte("c"), ClientTLSKeyPEM: []byte("k")}, true},
	}
	for _, c := range cases {
		if got := c.a.ClientTLSConfigured(); got != c.want {
			t.Errorf("%s: ClientTLSConfigured() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestUpstreamTLSEnabled(t *testing.T) {
	cases := map[string]bool{
		"":            false,
		"disable":     false,
		"disabled":    false,
		"off":         false,
		"false":       false,
		"prefer":      true,
		"require":     true,
		"verify-ca":   true,
		"verify-full": true,
		"REQUIRE":     true,
	}
	for mode, want := range cases {
		a := Agent{UpstreamTLSMode: mode}
		if got := a.UpstreamTLSEnabled(); got != want {
			t.Errorf("mode=%q: UpstreamTLSEnabled() = %v, want %v", mode, got, want)
		}
	}
}

func TestWireMtlsConfigured(t *testing.T) {
	cases := []struct {
		name string
		a    Agent
		want bool
	}{
		{"none", Agent{}, false},
		{"iam-auth", Agent{WireMtlsIamAuthEnabled: true}, true},
		{"cert-key-pair", Agent{WireMtlsClientCertPEM: []byte("c"), WireMtlsClientKeyPEM: []byte("k")}, true},
		{"cert-only", Agent{WireMtlsClientCertPEM: []byte("c")}, false},
		{"enroll-url", Agent{WireMtlsEnrollURL: "https://app"}, true},
	}
	for _, c := range cases {
		if got := c.a.WireMtlsConfigured(); got != c.want {
			t.Errorf("%s: WireMtlsConfigured() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLoadEdgeDefaultsAndFallbacks(t *testing.T) {
	t.Setenv("SKYBRIDGE_GATEWAY", "gw:7100")
	t.Setenv("SKYBRIDGE_AGENT_ID", "agent-a")
	e := LoadEdge()
	if e.GatewayAddr != "gw:7100" {
		t.Fatalf("expected EdgeGateway to fall back to SKYBRIDGE_GATEWAY, got %q", e.GatewayAddr)
	}
	if e.EdgeID != "agent-a" {
		t.Fatalf("expected EdgeID to fall back to SKYBRIDGE_AGENT_ID, got %q", e.EdgeID)
	}
	// StudioAgentID falls back to the raw SKYBRIDGE_EDGE_ID env var, not the already-resolved EdgeID
	// field — so setting only SKYBRIDGE_AGENT_ID (EdgeID's own fallback) does not propagate here.
	if e.StudioAgentID != "" {
		t.Fatalf("expected StudioAgentID empty when only SKYBRIDGE_AGENT_ID is set, got %q", e.StudioAgentID)
	}
	if e.StudioMaxSessions != 8 {
		t.Fatalf("expected default StudioMaxSessions 8, got %d", e.StudioMaxSessions)
	}
	// StudioTrustDomain is cosmetic and shared with TrustDomain/WireMtlsTrustDomain via the single
	// SKYBRIDGE_TRUST_DOMAIN env var — LoadEdge leaves it empty when unset rather than hardcoding a
	// default here; studiotransport.spiffeID applies its own default when given "".
	if e.StudioTrustDomain != "" {
		t.Fatalf("expected empty studio trust domain when SKYBRIDGE_TRUST_DOMAIN is unset, got %q", e.StudioTrustDomain)
	}
}

func TestLoadEdgeIamAuth(t *testing.T) {
	t.Setenv("SKYBRIDGE_IAM_AUTH", "true")
	t.Setenv("SKYBRIDGE_IAM_ENROLL_URL", "https://api.example.com")
	e := LoadEdge()
	if !e.IamAuthEnabled {
		t.Fatal("expected IamAuthEnabled true when SKYBRIDGE_IAM_AUTH is set")
	}
	if e.IamEnrollURL != "https://api.example.com" {
		t.Fatalf("expected IamEnrollURL %q, got %q", "https://api.example.com", e.IamEnrollURL)
	}
}

func TestLoadEdgeIamAuthDefaultsOff(t *testing.T) {
	e := LoadEdge()
	if e.IamAuthEnabled {
		t.Fatal("expected IamAuthEnabled false by default")
	}
}

func TestLoadEdgeConnectorKeyOverridesToken(t *testing.T) {
	t.Setenv("SKYBRIDGE_TOKEN", "one-time-enrollment-token")
	t.Setenv("SKYBRIDGE_CONNECTOR_KEY", "reusable-connector-key")
	e := LoadEdge()
	if e.ConnectorKey != "reusable-connector-key" {
		t.Fatalf("expected ConnectorKey %q, got %q", "reusable-connector-key", e.ConnectorKey)
	}
	if e.Token != "reusable-connector-key" {
		t.Fatalf("expected SKYBRIDGE_CONNECTOR_KEY to win over SKYBRIDGE_TOKEN, got %q", e.Token)
	}
	if !e.ReusableConnectorKeyConfigured() {
		t.Fatal("expected ReusableConnectorKeyConfigured true when SKYBRIDGE_CONNECTOR_KEY is set")
	}
}

func TestLoadEdgeConnectorKeyUnsetLeavesTokenAndDefaultsFalse(t *testing.T) {
	t.Setenv("SKYBRIDGE_TOKEN", "one-time-enrollment-token")
	e := LoadEdge()
	if e.ConnectorKey != "" {
		t.Fatalf("expected empty ConnectorKey by default, got %q", e.ConnectorKey)
	}
	if e.Token != "one-time-enrollment-token" {
		t.Fatalf("expected Token unchanged when SKYBRIDGE_CONNECTOR_KEY is unset, got %q", e.Token)
	}
	if e.ReusableConnectorKeyConfigured() {
		t.Fatal("expected ReusableConnectorKeyConfigured false by default")
	}
}

func TestLoadAgentConnectorKeyConfigured(t *testing.T) {
	t.Setenv("SKYBRIDGE_CONNECTOR_KEY", "reusable-connector-key")
	a := LoadAgent()
	if a.ConnectorKey != "reusable-connector-key" {
		t.Fatalf("expected ConnectorKey %q, got %q", "reusable-connector-key", a.ConnectorKey)
	}
	if !a.ReusableConnectorKeyConfigured() {
		t.Fatal("expected ReusableConnectorKeyConfigured true when SKYBRIDGE_CONNECTOR_KEY is set")
	}
}

func TestLoadAgentConnectorKeyUnsetDefaultsFalse(t *testing.T) {
	a := LoadAgent()
	if a.ConnectorKey != "" {
		t.Fatalf("expected empty ConnectorKey by default, got %q", a.ConnectorKey)
	}
	if a.ReusableConnectorKeyConfigured() {
		t.Fatal("expected ReusableConnectorKeyConfigured false by default")
	}
}

// TestLoadEdgeTrustDomainSharedAcrossIdentities verifies SKYBRIDGE_TRUST_DOMAIN feeds
// TrustDomain, StudioTrustDomain, and WireProxy.WireMtlsTrustDomain identically — the single knob
// that replaced SKYBRIDGE_SPIFFE_TRUST_DOMAIN / SKYBRIDGE_STUDIO_SPIFFE_TRUST_DOMAIN /
// SKYBRIDGE_WIRE_MTLS_TRUST_DOMAIN.
func TestLoadEdgeTrustDomainSharedAcrossIdentities(t *testing.T) {
	t.Setenv("SKYBRIDGE_TRUST_DOMAIN", "acme.example")
	e := LoadEdge()
	if e.TrustDomain != "acme.example" {
		t.Fatalf("expected TrustDomain %q, got %q", "acme.example", e.TrustDomain)
	}
	if e.StudioTrustDomain != "acme.example" {
		t.Fatalf("expected StudioTrustDomain %q, got %q", "acme.example", e.StudioTrustDomain)
	}
	if e.WireProxy.WireMtlsTrustDomain != "acme.example" {
		t.Fatalf("expected WireProxy.WireMtlsTrustDomain %q, got %q", "acme.example", e.WireProxy.WireMtlsTrustDomain)
	}
}

func TestLoadEdgeStudioAgentIDFallsBackToExplicitEdgeID(t *testing.T) {
	t.Setenv("SKYBRIDGE_EDGE_ID", "edge-1")
	e := LoadEdge()
	if e.StudioAgentID != "edge-1" {
		t.Fatalf("expected StudioAgentID to fall back to SKYBRIDGE_EDGE_ID, got %q", e.StudioAgentID)
	}
}

func TestLoadEdgeExplicitEdgeGatewayWins(t *testing.T) {
	t.Setenv("SKYBRIDGE_GATEWAY", "legacy-gw:7100")
	t.Setenv("SKYBRIDGE_EDGE_GATEWAY", "edge-gw:7100")
	e := LoadEdge()
	if e.GatewayAddr != "edge-gw:7100" {
		t.Fatalf("expected SKYBRIDGE_EDGE_GATEWAY to win, got %q", e.GatewayAddr)
	}
}

func TestStudioEnabled(t *testing.T) {
	if (Edge{}).StudioEnabled() {
		t.Fatal("expected StudioEnabled false when StudioGateway is empty")
	}
	if !(Edge{StudioGateway: "gw:7200"}).StudioEnabled() {
		t.Fatal("expected StudioEnabled true when StudioGateway is set")
	}
}

func TestWireProxyEnabled(t *testing.T) {
	cases := []struct {
		name string
		e    Edge
		want bool
	}{
		{"listener-no-upstream", Edge{WireProxy: Agent{Mode: ModeListener}}, false},
		{"listener-with-upstream", Edge{WireProxy: Agent{Mode: ModeListener, UpstreamAddr: "db:5432"}}, true},
		{"tunnel-no-gateway", Edge{WireProxy: Agent{Mode: ModeTunnel}}, false},
		{"tunnel-with-gateway", Edge{WireProxy: Agent{Mode: ModeTunnel, GatewayAddr: "gw:7100"}}, true},
	}
	for _, c := range cases {
		if got := c.e.WireProxyEnabled(); got != c.want {
			t.Errorf("%s: WireProxyEnabled() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLoadGatewayDefaults(t *testing.T) {
	g := LoadGateway()
	if g.AgentListen != ":8010" {
		t.Fatalf("expected default agent listen, got %q", g.AgentListen)
	}
	if g.RequireOrgID {
		t.Fatal("expected RequireOrgID false by default when no control plane URL is set")
	}
	if g.ClientConnPerMin != 0 {
		t.Fatalf("expected default 0 conn/min, got %d", g.ClientConnPerMin)
	}
	if g.OrgMaxConcurrentClients != 0 {
		t.Fatalf("expected default 0 (unlimited) concurrent-connection ceiling without a control plane URL, got %d", g.OrgMaxConcurrentClients)
	}
	if g.WireMtlsConfigured() {
		t.Fatal("expected WireMtlsConfigured false without a CA bundle")
	}
}

func TestLoadGatewayControlPlaneURLDefaultsRequireOrgIDAndRateLimit(t *testing.T) {
	t.Setenv("SKYBRIDGE_GW_CONTROL_PLANE_URL", "https://app.example.com")
	g := LoadGateway()
	if !g.RequireOrgID {
		t.Fatal("expected RequireOrgID to default true once a control plane URL is set")
	}
	if g.ClientConnPerMin != 60 {
		t.Fatalf("expected default rate limit 60 once a control plane URL is set, got %d", g.ClientConnPerMin)
	}
	if g.OrgMaxConcurrentClients != 1000 {
		t.Fatalf("expected default concurrent-connection ceiling 1000 once a control plane URL is set, got %d", g.OrgMaxConcurrentClients)
	}
}

// TestLoadGatewayExplicitOrgMaxConcurrentClientsOverridesDefault confirms an operator-set value
// takes priority over the control-plane-URL auto-default, matching ClientConnPerMin's own
// override behavior.
func TestLoadGatewayExplicitOrgMaxConcurrentClientsOverridesDefault(t *testing.T) {
	t.Setenv("SKYBRIDGE_GW_CONTROL_PLANE_URL", "https://app.example.com")
	t.Setenv("SKYBRIDGE_GW_ORG_MAX_CONCURRENT_CLIENTS", "5")
	g := LoadGateway()
	if g.OrgMaxConcurrentClients != 5 {
		t.Fatalf("expected explicit override 5, got %d", g.OrgMaxConcurrentClients)
	}
}

func TestLoadGatewayExplicitRequireOrgIDOverridesDefault(t *testing.T) {
	t.Setenv("SKYBRIDGE_GW_CONTROL_PLANE_URL", "https://app.example.com")
	t.Setenv("SKYBRIDGE_GW_REQUIRE_ORG_ID", "false")
	g := LoadGateway()
	if g.RequireOrgID {
		t.Fatal("expected explicit false to override the control-plane-URL default")
	}
}

func TestLoadGatewayParsesClientsJSON(t *testing.T) {
	t.Setenv("SKYBRIDGE_GW_CLIENTS", `[{"addr":":5433","org_id":"org-1","target":"prod"}]`)
	g := LoadGateway()
	if len(g.Clients) != 1 || g.Clients[0].OrgID != "org-1" {
		t.Fatalf("unexpected clients: %v", g.Clients)
	}
}

func TestLoadGatewayClientsInvalidJSONReturnsNil(t *testing.T) {
	t.Setenv("SKYBRIDGE_GW_CLIENTS", `not json`)
	g := LoadGateway()
	if g.Clients != nil {
		t.Fatalf("expected nil clients on invalid JSON, got %v", g.Clients)
	}
}

func TestLoadGatewayWireMtlsConfigured(t *testing.T) {
	t.Setenv("SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM", "ca-bundle")
	g := LoadGateway()
	if !g.WireMtlsConfigured() {
		t.Fatal("expected WireMtlsConfigured true once a CA bundle is set")
	}
}

func TestTruthy(t *testing.T) {
	truthyVals := []string{"1", "true", "TRUE", "yes", "on", " 1 "}
	for _, v := range truthyVals {
		if !truthy(v) {
			t.Errorf("truthy(%q) = false, want true", v)
		}
	}
	falsyVals := []string{"", "0", "false", "no", "off", "garbage"}
	for _, v := range falsyVals {
		if truthy(v) {
			t.Errorf("truthy(%q) = true, want false", v)
		}
	}
}

func TestEnvTrimsAndFallsBackToDefault(t *testing.T) {
	t.Setenv("SKYBRIDGE_TEST_KEY", "  spaced-value  ")
	if got := env("SKYBRIDGE_TEST_KEY", "def"); got != "spaced-value" {
		t.Fatalf("expected trimmed value, got %q", got)
	}
	if got := env("SKYBRIDGE_UNSET_KEY_XYZ", "def"); got != "def" {
		t.Fatalf("expected default for unset key, got %q", got)
	}
}
