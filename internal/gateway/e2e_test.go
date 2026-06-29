package gateway_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/agent"
	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/gateway"
	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire"
)

// upperEngine is a stand-in wire engine: it forwards client->upstream verbatim and upper-cases the
// upstream->client direction. That stands in for "the agent transformed the bytes" so the test can
// assert the full client -> gateway -> tunnel -> agent -> upstream path (both directions) works.
type upperEngine struct{}

func (upperEngine) Name() string { return "upper" }

func (upperEngine) Proxy(_ context.Context, client, upstream net.Conn, _ mask.Masker) error {
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, client); errc <- e }()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if _, werr := client.Write(bytes.ToUpper(buf[:n])); werr != nil {
					errc <- werr
					return
				}
			}
			if err != nil {
				errc <- err
				return
			}
		}
	}()
	err := <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	return err
}

func silent() *log.Logger { return log.New(io.Discard, "", 0) }

func TestEndToEndTunnelRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New("tok", silent())
	rec := &recordingStore{}
	g.SetStore(rec)

	// Agent <-> gateway over an in-memory pipe.
	agentGW, agentLocal := net.Pipe()
	go func() { _ = g.ServeAgent(agentGW) }()

	cfg := config.Agent{
		Mode:    config.ModeTunnel,
		AgentID: "a1",
		OrgID:   "org-1",
		Token:   "tok",
		Targets: []tunnel.Target{{
			Name: "db", Addr: "upstream:0", DBType: "upper",
			ResourceRoleID: "role-1", ActorEmail: "owner@example.com",
		}},
	}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()

	// Wait for the agent to register its target.
	if !waitForTarget(g, "db", 2*time.Second) {
		t.Fatal("agent did not register target in time")
	}

	// Native client <-> gateway over an in-memory pipe.
	clientGW, client := net.Pipe()
	go func() { _ = g.ServeClient(clientGW, "db") }()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(got) != "PING" {
		t.Fatalf("got %q want PING (round trip through the tunnel)", got)
	}

	// Close the client so the relay ends and the session is recorded.
	_ = client.Close()
	if !rec.waitEnded(2 * time.Second) {
		t.Fatal("session end was not recorded")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.started.Target != "db" || rec.started.DBType != "upper" || rec.started.OrgID != "org-1" {
		t.Fatalf("start record wrong: %+v", rec.started)
	}
	// Attribution from the registered target binding must reach the control plane so the session
	// is owned (not recorded unattributed).
	if rec.started.ResourceRoleID != "role-1" || rec.started.ActorEmail != "owner@example.com" {
		t.Fatalf("attribution not relayed: role=%q actor=%q", rec.started.ResourceRoleID, rec.started.ActorEmail)
	}
	if rec.ended.BytesUp == 0 || rec.ended.BytesDown == 0 {
		t.Fatalf("expected non-zero byte counts, got up=%d down=%d", rec.ended.BytesUp, rec.ended.BytesDown)
	}
	if rec.endedID != "rec-1" {
		t.Fatalf("end called with id %q, want rec-1", rec.endedID)
	}
}

type recordingStore struct {
	mu      sync.Mutex
	started gateway.SessionRecord
	ended   gateway.SessionResult
	endedID string
	done    bool
}

func (s *recordingStore) SessionStarted(_ context.Context, rec gateway.SessionRecord) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = rec
	return "rec-1", nil
}

func (s *recordingStore) SessionEnded(_ context.Context, id string, res gateway.SessionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endedID = id
	s.ended = res
	s.done = true
	return nil
}

func (s *recordingStore) waitEnded(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		done := s.done
		s.mu.Unlock()
		if done {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// pgStartupBytes builds a Postgres StartupMessage carrying a user parameter (test helper).
func pgStartupBytes(user string) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, 196608) // protocol version 3.0
	for _, kv := range []string{"user", user, "database", "prod"} {
		body = append(body, []byte(kv)...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	copy(out[4:], body)
	return out
}

// TestRelayAttributesByLoginUsername proves the gateway sniffs the DB login off the relayed
// handshake and reports it at close, so the control plane can attribute the session to its owner.
func TestRelayAttributesByLoginUsername(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g := gateway.New("", silent())
	rec := &recordingStore{}
	g.SetStore(rec)

	agentGW, agentLocal := net.Pipe()
	go func() { _ = g.ServeAgent(agentGW) }()

	cfg := config.Agent{
		Mode:    config.ModeTunnel,
		AgentID: "a1",
		OrgID:   "org-1",
		Targets: []tunnel.Target{{Name: "pg", Addr: "upstream:0", DBType: "postgres", ResourceRoleID: "role-1"}},
	}
	deps := agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}
	go func() { _ = agent.ServeTunnelConn(ctx, agentLocal, cfg, deps, silent()) }()
	if !waitForTarget(g, "pg", 2*time.Second) {
		t.Fatal("agent did not register target in time")
	}

	clientGW, client := net.Pipe()
	go func() { _ = g.ServeClient(clientGW, "pg") }()

	if _, err := client.Write(pgStartupBytes("alice")); err != nil {
		t.Fatal(err)
	}
	// Drain whatever the echo upstream sends back so the relay isn't blocked, then close.
	go func() { _, _ = io.Copy(io.Discard, client) }()
	time.Sleep(50 * time.Millisecond)
	_ = client.Close()

	if !rec.waitEnded(2 * time.Second) {
		t.Fatal("session end was not recorded")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.started.ResourceRoleID != "role-1" {
		t.Fatalf("resource role not relayed: %+v", rec.started)
	}
	if rec.ended.DBUsername != "alice" {
		t.Fatalf("db username not sniffed/relayed: %q", rec.ended.DBUsername)
	}
}

func TestServeClientNoAgent(t *testing.T) {
	g := gateway.New("", silent())
	_, client := net.Pipe()
	if err := g.ServeClient(client, "missing"); err != gateway.ErrNoAgent {
		t.Fatalf("want ErrNoAgent, got %v", err)
	}
}

func TestServeAgentRejectsBadToken(t *testing.T) {
	g := gateway.New("right", silent())
	gw, local := net.Pipe()
	go func() { _ = g.ServeAgent(gw) }()

	cfg := config.Agent{Mode: config.ModeTunnel, AgentID: "a1", Token: "wrong", Targets: []tunnel.Target{{Name: "db", Addr: "x:0", DBType: "upper"}}}
	err := agent.ServeTunnelConn(context.Background(), local, cfg, agent.Deps{
		Dial:   echoDialer,
		Engine: func(string) (wire.Engine, error) { return upperEngine{}, nil },
		Masker: mask.Noop{},
	}, silent())
	if err == nil {
		t.Fatal("expected registration rejection for bad token")
	}
}

// echoDialer returns a fresh in-memory upstream that echoes whatever is written to it.
func echoDialer(_ context.Context, _, _ string) (net.Conn, error) {
	c, s := net.Pipe()
	go func() { _, _ = io.Copy(s, s) }()
	return c, nil
}

func waitForTarget(g *gateway.Gateway, name string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, tname := range g.Targets() {
			if tname == name {
				return true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
