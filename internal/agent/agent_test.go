package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/pathlabel/remotestore"
	"github.com/curlix-io/skybridge/internal/wire"
)

// fakeEngine is a minimal wire.Engine for testing proxyConn's dispatch without a real protocol.
type fakeEngine struct {
	proxyCalled bool
	name        string
}

func (f *fakeEngine) Name() string { return f.name }
func (f *fakeEngine) Proxy(context.Context, net.Conn, net.Conn, mask.Masker, wire.Recorder) error {
	f.proxyCalled = true
	return nil
}

// fakeInjectingEngine additionally implements wire.InjectingEngine.
type fakeInjectingEngine struct {
	fakeEngine
	injectCalled bool
}

func (f *fakeInjectingEngine) ProxyInject(context.Context, net.Conn, net.Conn, mask.Masker, wire.CredentialResolver, wire.Recorder) error {
	f.injectCalled = true
	return nil
}

func noopResolver(context.Context, map[string]string, string) (wire.UpstreamCredential, error) {
	return wire.UpstreamCredential{}, nil
}

func TestProxyConnUsesInjectionWhenResolverAndEngineSupportIt(t *testing.T) {
	e := &fakeInjectingEngine{}
	client, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	if err := proxyConn(context.Background(), e, client, upstream, mask.Noop{}, noopResolver, wire.NoopRecorder{}); err != nil {
		t.Fatal(err)
	}
	if !e.injectCalled || e.proxyCalled {
		t.Fatalf("expected ProxyInject to be used, got injectCalled=%v proxyCalled=%v", e.injectCalled, e.proxyCalled)
	}
}

func TestProxyConnFallsBackToVerbatimWithoutResolver(t *testing.T) {
	e := &fakeInjectingEngine{}
	client, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	if err := proxyConn(context.Background(), e, client, upstream, mask.Noop{}, nil, wire.NoopRecorder{}); err != nil {
		t.Fatal(err)
	}
	if e.injectCalled || !e.proxyCalled {
		t.Fatalf("expected verbatim Proxy without a resolver, got injectCalled=%v proxyCalled=%v", e.injectCalled, e.proxyCalled)
	}
}

func TestProxyConnFallsBackToVerbatimWhenEngineDoesNotSupportInjection(t *testing.T) {
	e := &fakeEngine{name: "mongodb"}
	client, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	if err := proxyConn(context.Background(), e, client, upstream, mask.Noop{}, noopResolver, wire.NoopRecorder{}); err != nil {
		t.Fatal(err)
	}
	if !e.proxyCalled {
		t.Fatal("expected verbatim Proxy when the engine does not implement InjectingEngine")
	}
}

func TestEngineForSelectsByDBType(t *testing.T) {
	cases := map[string]string{"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "mongodb": "mongodb", "mongo": "mongodb"}
	for in, wantName := range cases {
		engine, err := EngineFor(in)
		if err != nil {
			t.Fatalf("EngineFor(%q): %v", in, err)
		}
		if engine.Name() != wantName {
			t.Errorf("EngineFor(%q).Name() = %q, want %q", in, engine.Name(), wantName)
		}
	}
	if _, err := EngineFor("oracle"); err == nil {
		t.Fatal("expected an error for an unsupported db type")
	}
}

func TestBuildMaskerNoopWhenNothingConfigured(t *testing.T) {
	m := BuildMasker(config.Agent{})
	if _, ok := m.(mask.Noop); !ok {
		t.Fatalf("expected mask.Noop, got %T", m)
	}
}

func TestBuildMaskerWithOverlayReturnsHandleWhenOverlayConfigured(t *testing.T) {
	m, overlay, _, _, _ := buildMaskerWithOverlay(config.Agent{PIIOverlay: map[string]mask.OverlayRule{"email": {Token: "[EMAIL]"}}})
	if overlay == nil {
		t.Fatal("expected a non-nil overlay handle")
	}
	if _, ok := m.(*mask.Chain); !ok {
		t.Fatalf("expected a Chain when an overlay is active, got %T", m)
	}
}

func TestBuildMaskerWithOverlayNilHandleWhenNoOverlay(t *testing.T) {
	_, overlay, _, _, _ := buildMaskerWithOverlay(config.Agent{MaskAnalyzeURL: "http://a", MaskAnonymizeURL: "http://b"})
	if overlay != nil {
		t.Fatal("expected a nil overlay handle when no overlay is configured")
	}
}

// TestBuildTrafficSampler_DisabledWithoutLLMEndpointOrStore confirms buildTrafficSampler stays a
// safe no-op unless both a store (PathLabelURL configured) and an LLM endpoint are set — matching
// every other optional integration's "nothing configured -> nil" contract.
func TestBuildTrafficSampler_DisabledWithoutLLMEndpointOrStore(t *testing.T) {
	if buf := buildTrafficSampler(config.Agent{}, nil); buf != nil {
		t.Fatal("expected nil with neither LLM endpoint nor store configured")
	}
	store := remotestore.New(config.Agent{PathLabelURL: "http://example.invalid"}, nil)
	if buf := buildTrafficSampler(config.Agent{}, store); buf != nil {
		t.Fatal("expected nil with a store but no LLM endpoint configured")
	}
	if buf := buildTrafficSampler(config.Agent{TrafficSamplerLLMEndpoint: "http://example.invalid"}, nil); buf != nil {
		t.Fatal("expected nil with an LLM endpoint but no store configured")
	}
}

// TestBuildTrafficSampler_EnabledWithBothConfigured confirms buildTrafficSampler returns a usable
// Buffer once both prerequisites are set (see docs/AI_PATH_LABELLING_DESIGN.md §5.2).
func TestBuildTrafficSampler_EnabledWithBothConfigured(t *testing.T) {
	store := remotestore.New(config.Agent{PathLabelURL: "http://example.invalid"}, nil)
	buf := buildTrafficSampler(config.Agent{TrafficSamplerLLMEndpoint: "http://example.invalid"}, store)
	if buf == nil {
		t.Fatal("expected a non-nil Buffer with both LLM endpoint and store configured")
	}
	buf.Observe("org1:postgres:app:users", "email", "a@example.com")
	if len(buf.Fields()) != 1 {
		t.Fatalf("expected the buffer to be usable, got fields=%v", buf.Fields())
	}
}

func TestMaskingMode(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Agent
		want string
	}{
		{"none", config.Agent{}, "none"},
		{"remote-only", config.Agent{MaskAnalyzeURL: "http://a"}, "remote"},
		{"overlay-only", config.Agent{PIIOverlay: map[string]mask.OverlayRule{"e": {Token: "x"}}}, "overlay"},
		{"overlay-dynamic", config.Agent{PIIOverlayURL: "http://cp"}, "overlay(dynamic)"},
		{"both", config.Agent{MaskAnalyzeURL: "http://a", PIIOverlay: map[string]mask.OverlayRule{"e": {Token: "x"}}}, "remote+overlay"},
		{"both-dynamic", config.Agent{MaskAnalyzeURL: "http://a", PIIOverlayURL: "http://cp"}, "remote+overlay(dynamic)"},
		{"remote-strict", config.Agent{MaskAnalyzeURL: "http://a", MaskMode: config.ModeStrict}, "remote(strict)"},
		{"overlay-only-strict-ignored", config.Agent{PIIOverlay: map[string]mask.OverlayRule{"e": {Token: "x"}}, MaskMode: config.ModeStrict}, "overlay"},
	}
	for _, c := range cases {
		if got := MaskingMode(c.cfg); got != c.want {
			t.Errorf("%s: MaskingMode() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDepsWithDefaultsFillsInMissingCollaborators(t *testing.T) {
	d := Deps{}.withDefaults(config.Agent{})
	if d.Dial == nil || d.Engine == nil || d.Masker == nil {
		t.Fatalf("expected all collaborators filled in, got %+v", d)
	}
}

func TestDepsWithDefaultsPreservesInjectedCollaborators(t *testing.T) {
	customMasker := mask.Noop{}
	d := Deps{Masker: customMasker}.withDefaults(config.Agent{})
	if d.Masker != mask.Masker(customMasker) {
		t.Fatal("expected injected masker to be preserved")
	}
}

func TestLogCredentialModeNoopWhenInjectionDisabled(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{}, &fakeEngine{name: "postgres"}, nil, slog.New(slog.NewTextHandler(&buf, nil)))
	if buf.Len() != 0 {
		t.Fatalf("expected no log output when injection is disabled, got %q", buf.String())
	}
}

func TestLogCredentialModeWarnsWhenResolverNil(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{InjectCredentials: true}, &fakeEngine{name: "postgres"}, nil, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("falling back to verbatim")) {
		t.Fatalf("expected a fallback warning, got %q", buf.String())
	}
}

func TestLogCredentialModeWarnsWhenEngineDoesNotSupportInjection(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{InjectCredentials: true}, &fakeEngine{name: "mongodb"}, noopResolver, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("does not support it yet")) {
		t.Fatalf("expected an unsupported-engine warning, got %q", buf.String())
	}
}

func TestLogCredentialModeEnabledWarnsWithoutClientTLS(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{InjectCredentials: true}, &fakeInjectingEngine{}, noopResolver, slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("ENABLED")) {
		t.Fatalf("expected an enabled message, got %q", out)
	}
	if !bytes.Contains(buf.Bytes(), []byte("client TLS is OFF")) {
		t.Fatalf("expected a client-TLS-off warning, got %q", out)
	}
}

func TestLogCredentialModeEnabledSilentWarningWithClientTLS(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{InjectCredentials: true, ClientTLSSelfSigned: true}, &fakeInjectingEngine{}, noopResolver, slog.New(slog.NewTextHandler(&buf, nil)))
	if bytes.Contains(buf.Bytes(), []byte("client TLS is OFF")) {
		t.Fatalf("expected no client-TLS-off warning when TLS is configured, got %q", buf.String())
	}
}

func TestLogCredentialModeDefaultsNilLogger(t *testing.T) {
	// A nil logger must fall back to slog.Default() rather than panic, even down the warning path.
	logCredentialMode(config.Agent{InjectCredentials: true}, &fakeEngine{name: "postgres"}, nil, nil)
}

func TestLogClientTLSModeDefaultsNilLogger(t *testing.T) {
	tlsCfg := agentTestTLSConfig(t)
	// A nil logger must fall back to slog.Default() rather than panic.
	logClientTLSMode(config.Agent{ClientTLSSelfSigned: true}, tlsCfg, &fakeEngine{name: "postgres"}, nil)
}

// TestLogClientTLSModeWarnsWhenNotConfigured is the regression test for the "plaintext-by-default,
// no signal either way" gap: before this warning existed, a fully plaintext deployment (the
// default) produced zero log output about it, indistinguishable from a healthy TLS-terminated one
// except by the absence of a message.
func TestLogClientTLSModeWarnsWhenNotConfigured(t *testing.T) {
	var buf bytes.Buffer
	logClientTLSMode(config.Agent{}, nil, &fakeEngine{name: "postgres"}, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("client TLS is OFF")) {
		t.Fatalf("expected a plaintext-client-hop warning, got %q", buf.String())
	}
}

func TestLogClientTLSModeNoopWhenConfigButNilTLS(t *testing.T) {
	var buf bytes.Buffer
	logClientTLSMode(config.Agent{ClientTLSSelfSigned: true}, nil, &fakeEngine{name: "postgres"}, slog.New(slog.NewTextHandler(&buf, nil)))
	if buf.Len() != 0 {
		t.Fatalf("expected no output when clientTLS is nil (builder already logged), got %q", buf.String())
	}
}

func TestLogClientTLSModeReportsPerEngine(t *testing.T) {
	tlsCfg := agentTestTLSConfig(t)
	cases := map[string]string{"postgres": "ENABLED", "mysql": "ENABLED for MySQL", "mongodb": "ENABLED for MongoDB", "oracle": "does not"}
	for name, want := range cases {
		var buf bytes.Buffer
		logClientTLSMode(config.Agent{ClientTLSSelfSigned: true}, tlsCfg, &fakeEngine{name: name}, slog.New(slog.NewTextHandler(&buf, nil)))
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("engine %q: expected log to contain %q, got %q", name, want, buf.String())
		}
	}
}

func TestRunListenerRequiresUpstreamAddr(t *testing.T) {
	err := RunListener(context.Background(), config.Agent{}, nil)
	if err == nil {
		t.Fatal("expected an error when SKYBRIDGE_UPSTREAM is unset")
	}
}

func TestRunTunnelRequiresGatewayAddr(t *testing.T) {
	err := RunTunnel(context.Background(), config.Agent{}, Deps{}, nil)
	if err == nil {
		t.Fatal("expected an error when SKYBRIDGE_GATEWAY is unset")
	}
}

func TestRunTunnelRequiresWireMtlsOrConnectorKey(t *testing.T) {
	err := RunTunnel(context.Background(), config.Agent{GatewayAddr: "127.0.0.1:0"}, Deps{}, nil)
	if err == nil {
		t.Fatal("expected an error when neither wire mTLS nor SKYBRIDGE_CONNECTOR_KEY is configured")
	}
	if !strings.Contains(err.Error(), "SKYBRIDGE_CONNECTOR_KEY") {
		t.Fatalf("expected the fail-fast error to mention SKYBRIDGE_CONNECTOR_KEY as an alternative, got: %v", err)
	}
}

// TestRunTunnelConnectorKeyConfiguredBypassesMtlsRequirement confirms SKYBRIDGE_CONNECTOR_KEY
// alone satisfies RunTunnel's fail-fast auth-configured check (previously wire mTLS was the only
// option) — cancelling ctx before the dial loop starts means a nil return proves the fail-fast
// branch was never hit, without needing a live gateway stub.
func TestRunTunnelConnectorKeyConfiguredBypassesMtlsRequirement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RunTunnel(ctx, config.Agent{GatewayAddr: "127.0.0.1:0", ConnectorKey: "reusable-key"}, Deps{}, nil)
	if err != nil {
		t.Fatalf("expected nil (ctx already cancelled before the dial loop) when ConnectorKey is set without wire mTLS, got: %v", err)
	}
}

func TestBuildMaskerWithPathLabelSyncNoopWhenNothingConfigured(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, detector, store := BuildMaskerWithPathLabelSync(ctx, config.Agent{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, ok := m.(mask.Noop); !ok {
		t.Fatalf("expected mask.Noop, got %T", m)
	}
	if detector != nil {
		t.Fatalf("expected nil detector, got %v", detector)
	}
	if store != nil {
		t.Fatalf("expected nil store, got %v", store)
	}
}

func TestBuildMaskerWithPathLabelSyncReturnsDetectorWhenRemoteEnabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.Agent{MaskAnalyzeURL: "http://a", MaskAnonymizeURL: "http://b"}
	m, detector, store := BuildMaskerWithPathLabelSync(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if m == nil {
		t.Fatal("expected a non-nil masker")
	}
	if detector == nil || !detector.Enabled() {
		t.Fatalf("expected an enabled detector when Presidio is configured, got %v", detector)
	}
	if store != nil {
		t.Fatalf("expected nil store without SKYBRIDGE_PATH_LABEL_URL, got %v", store)
	}
}

func TestBuildMaskerWithPathLabelSyncStartsPathLabelStore(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.Agent{PathLabelURL: "http://127.0.0.1:0/path-labels"}
	m, _, store := BuildMaskerWithPathLabelSync(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if m == nil {
		t.Fatal("expected a non-nil masker")
	}
	if store == nil {
		t.Fatal("expected a non-nil path-label store when SKYBRIDGE_PATH_LABEL_URL is set")
	}
}

func TestSleepReturnsFalseOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A non-trivial duration keeps this deterministic: with d=0, time.After(0) fires immediately too
	// and races the already-closed ctx.Done() in sleep's select.
	if sleep(ctx, time.Minute) {
		t.Fatal("expected sleep to report false on an already-cancelled context")
	}
}

func TestJitteredBackoffStaysInHalfOpenRange(t *testing.T) {
	d := 10 * time.Second
	for i := 0; i < 200; i++ {
		got := jitteredBackoff(d)
		if got < d/2 || got >= d {
			t.Fatalf("jitteredBackoff(%v) = %v, want in [%v, %v)", d, got, d/2, d)
		}
	}
}

func TestJitteredBackoffZeroIsZero(t *testing.T) {
	if got := jitteredBackoff(0); got != 0 {
		t.Fatalf("jitteredBackoff(0) = %v, want 0", got)
	}
}

func TestNextBackoffDoublesUntilCap(t *testing.T) {
	d := reconnectBaseBackoff
	for d < reconnectMaxBackoff {
		next := nextBackoff(d)
		want := d * 2
		if want > reconnectMaxBackoff {
			want = reconnectMaxBackoff
		}
		if next != want {
			t.Fatalf("nextBackoff(%v) = %v, want %v", d, next, want)
		}
		d = next
	}
	// Once at the cap, it must stay there rather than overflow past it.
	if got := nextBackoff(reconnectMaxBackoff); got != reconnectMaxBackoff {
		t.Fatalf("nextBackoff(reconnectMaxBackoff) = %v, want %v (stay capped)", got, reconnectMaxBackoff)
	}
}

// TestRecoverConnStopsPanicAndLogs is the regression test for RunListener's/serveStream's panic
// safety net: a panic inside a per-connection goroutine (e.g. a wire-engine parsing bug wire.SafeGo
// didn't already turn into an error) must stop right here, not crash the whole agent process and
// take down every other tenant's connection sharing it. Before recoverConn existed, calling this
// function's body directly (a bare panic with nothing deferred above it) would have crashed the
// test binary itself.
func TestRecoverConnStopsPanicAndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	func() {
		defer recoverConn(logger, nil)
		panic("simulated parsing bug on malformed wire data")
	}()

	if !bytes.Contains(buf.Bytes(), []byte("recovered from panic")) {
		t.Fatalf("expected a recovered-panic log line, got %q", buf.String())
	}
}

// TestRecoverConnIncludesRemoteAddrWhenGiven confirms the client address is attributable in the
// log line when the caller has one (RunListener's accept-loop goroutine does; serveStream doesn't).
func TestRecoverConnIncludesRemoteAddrWhenGiven(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	addr, err := net.ResolveTCPAddr("tcp", "203.0.113.5:12345")
	if err != nil {
		t.Fatalf("ResolveTCPAddr: %v", err)
	}

	func() {
		defer recoverConn(logger, addr)
		panic("simulated parsing bug")
	}()

	if !bytes.Contains(buf.Bytes(), []byte("203.0.113.5:12345")) {
		t.Fatalf("expected the remote address in the log line, got %q", buf.String())
	}
}

// TestRecoverConnNoopWithoutPanic confirms recoverConn is a harmless no-op on the normal,
// non-panicking path — it must never itself log or otherwise misbehave absent a real panic.
func TestRecoverConnNoopWithoutPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	func() {
		defer recoverConn(logger, nil)
	}()

	if buf.Len() != 0 {
		t.Fatalf("expected no log output absent a panic, got %q", buf.String())
	}
}

// TestRecoverBackgroundStopsPanicAndLogs is the regression test for the periodic sync loops'
// panic safety net (startOverlaySync, startRecognizersSync): a panic triggered by a malformed or
// adversarial control-plane response must stop only that one background loop, not crash the
// whole agent process and every live database session sharing it.
func TestRecoverBackgroundStopsPanicAndLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	func() {
		defer recoverBackground(logger, "test sync loop")
		panic("simulated parsing bug on a malformed control-plane response")
	}()

	if !bytes.Contains(buf.Bytes(), []byte("recovered from panic in test sync loop")) {
		t.Fatalf("expected a recovered-panic log line naming the loop, got %q", buf.String())
	}
}

func TestRecoverBackgroundNoopWithoutPanic(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	func() {
		defer recoverBackground(logger, "test sync loop")
	}()

	if buf.Len() != 0 {
		t.Fatalf("expected no log output absent a panic, got %q", buf.String())
	}
}

// TestCaCertPool is the regression test for bearer-mode's wire tunnel TLS: a gateway cert signed
// by a private CA (embedded in a SKYBRIDGE_KEY's ca= param) must be trusted via cfg.CABundle
// instead of only ever trusting system roots (which failed every dial with "x509: certificate
// signed by unknown authority").
func TestCaCertPool(t *testing.T) {
	if pool, ok := caCertPool(nil); ok || pool != nil {
		t.Fatalf("expected (nil, false) for an empty bundle, got (%v, %v)", pool, ok)
	}
	if pool, ok := caCertPool([]byte("not a pem")); ok || pool != nil {
		t.Fatalf("expected (nil, false) for an unparseable bundle, got (%v, %v)", pool, ok)
	}

	certPEM, _, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	if pool, ok := caCertPool(certPEM); !ok || pool == nil {
		t.Fatal("expected a valid pool for a well-formed PEM certificate")
	}
}
