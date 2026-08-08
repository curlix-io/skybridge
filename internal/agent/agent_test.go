package agent

import (
	"bytes"
	"context"
	"log"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
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
	m, overlay := buildMaskerWithOverlay(config.Agent{PIIOverlay: map[string]string{"email": "[EMAIL]"}})
	if overlay == nil {
		t.Fatal("expected a non-nil overlay handle")
	}
	if _, ok := m.(*mask.Chain); !ok {
		t.Fatalf("expected a Chain when an overlay is active, got %T", m)
	}
}

func TestBuildMaskerWithOverlayNilHandleWhenNoOverlay(t *testing.T) {
	_, overlay := buildMaskerWithOverlay(config.Agent{MaskAnalyzeURL: "http://a", MaskAnonymizeURL: "http://b"})
	if overlay != nil {
		t.Fatal("expected a nil overlay handle when no overlay is configured")
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
		{"overlay-only", config.Agent{PIIOverlay: map[string]string{"e": "x"}}, "overlay"},
		{"overlay-dynamic", config.Agent{PIIOverlayURL: "http://cp"}, "overlay(dynamic)"},
		{"both", config.Agent{MaskAnalyzeURL: "http://a", PIIOverlay: map[string]string{"e": "x"}}, "remote+overlay"},
		{"both-dynamic", config.Agent{MaskAnalyzeURL: "http://a", PIIOverlayURL: "http://cp"}, "remote+overlay(dynamic)"},
		{"remote-strict", config.Agent{MaskAnalyzeURL: "http://a", MaskMode: config.ModeStrict}, "remote(strict)"},
		{"overlay-only-strict-ignored", config.Agent{PIIOverlay: map[string]string{"e": "x"}, MaskMode: config.ModeStrict}, "overlay"},
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
	logCredentialMode(config.Agent{}, &fakeEngine{name: "postgres"}, nil, log.New(&buf, "", 0))
	if buf.Len() != 0 {
		t.Fatalf("expected no log output when injection is disabled, got %q", buf.String())
	}
}

func TestLogCredentialModeWarnsWhenResolverNil(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{InjectCredentials: true}, &fakeEngine{name: "postgres"}, nil, log.New(&buf, "", 0))
	if !bytes.Contains(buf.Bytes(), []byte("falling back to verbatim")) {
		t.Fatalf("expected a fallback warning, got %q", buf.String())
	}
}

func TestLogCredentialModeWarnsWhenEngineDoesNotSupportInjection(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{InjectCredentials: true}, &fakeEngine{name: "mongodb"}, noopResolver, log.New(&buf, "", 0))
	if !bytes.Contains(buf.Bytes(), []byte("does not support it yet")) {
		t.Fatalf("expected an unsupported-engine warning, got %q", buf.String())
	}
}

func TestLogCredentialModeEnabledWarnsWithoutClientTLS(t *testing.T) {
	var buf bytes.Buffer
	logCredentialMode(config.Agent{InjectCredentials: true}, &fakeInjectingEngine{}, noopResolver, log.New(&buf, "", 0))
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
	logCredentialMode(config.Agent{InjectCredentials: true, ClientTLSSelfSigned: true}, &fakeInjectingEngine{}, noopResolver, log.New(&buf, "", 0))
	if bytes.Contains(buf.Bytes(), []byte("client TLS is OFF")) {
		t.Fatalf("expected no client-TLS-off warning when TLS is configured, got %q", buf.String())
	}
}

func TestLogClientTLSModeNoopWhenNotConfigured(t *testing.T) {
	var buf bytes.Buffer
	logClientTLSMode(config.Agent{}, nil, &fakeEngine{name: "postgres"}, log.New(&buf, "", 0))
	if buf.Len() != 0 {
		t.Fatalf("expected no output when client TLS is not configured, got %q", buf.String())
	}
}

func TestLogClientTLSModeNoopWhenConfigButNilTLS(t *testing.T) {
	var buf bytes.Buffer
	logClientTLSMode(config.Agent{ClientTLSSelfSigned: true}, nil, &fakeEngine{name: "postgres"}, log.New(&buf, "", 0))
	if buf.Len() != 0 {
		t.Fatalf("expected no output when clientTLS is nil (builder already logged), got %q", buf.String())
	}
}

func TestLogClientTLSModeReportsPerEngine(t *testing.T) {
	tlsCfg := agentTestTLSConfig(t)
	cases := map[string]string{"postgres": "ENABLED", "mysql": "ENABLED for MySQL", "mongodb": "does not"}
	for name, want := range cases {
		var buf bytes.Buffer
		logClientTLSMode(config.Agent{ClientTLSSelfSigned: true}, tlsCfg, &fakeEngine{name: name}, log.New(&buf, "", 0))
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

func TestSleepReturnsFalseOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A non-trivial duration keeps this deterministic: with d=0, time.After(0) fires immediately too
	// and races the already-closed ctx.Done() in sleep's select.
	if sleep(ctx, time.Minute) {
		t.Fatal("expected sleep to report false on an already-cancelled context")
	}
}
