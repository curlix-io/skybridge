// Package gateway is the relay-side Skybridge control plane. Agents dial in (egress-only) and
// register the database targets they can reach; native clients connect to gateway listeners and the
// gateway relays their bytes over the registered agent's tunnel. Because the agent runs the wire
// engine + masker against the upstream DB, the gateway only ever sees already-masked bytes.
//
// State that must outlive a process (sessions, audit, leases) belongs in an external control plane,
// which the gateway reports to as the single writer — see CONTRACT.md. This package owns the
// in-memory agent registry and the relay; durable session/lease recording plugs in behind the
// Store interface.
package gateway

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/curlix-io/skybridge/internal/tunnel"
)

// ErrNoAgent is returned when no registered agent can serve a requested target.
var ErrNoAgent = errors.New("gateway: no agent registered for target")

// ErrMissingOrgID is returned when an agent or relay path lacks organization_id.
var ErrMissingOrgID = errors.New("gateway: missing organization_id")

const storeTimeout = 5 * time.Second

// Gateway holds the live agent registry and relays client connections over agent tunnels.
type Gateway struct {
	authToken    string
	log          *log.Logger
	store        Store
	admitter     WireAdmitter
	requireOrgID bool
	connLimiter  ConnRateLimiter

	mu      sync.RWMutex
	agents  map[string]*agentConn // agent id -> connection
	targets map[string]*agentConn // target name -> serving agent (last registrant wins)
}

type agentConn struct {
	id      string
	orgID   string
	sess    *tunnel.Session
	targets []tunnel.Target
}

// target returns the registered binding for a target name (used for attribution lookups).
func (ac *agentConn) target(name string) (tunnel.Target, bool) {
	for _, t := range ac.targets {
		if t.Name == name {
			return t, true
		}
	}
	return tunnel.Target{}, false
}

// New creates a Gateway. authToken (if non-empty) is required from agents at registration.
func New(authToken string, logger *log.Logger) *Gateway {
	if logger == nil {
		logger = log.Default()
	}
	return &Gateway{
		authToken: authToken,
		log:       logger,
		store:     NoopStore{},
		admitter:  NoopWireAdmitter{},
		connLimiter: NoopConnRateLimiter{},
		agents:    make(map[string]*agentConn),
		targets:   make(map[string]*agentConn),
	}
}

// SetStore installs a session-recording store (defaults to NoopStore).
func (g *Gateway) SetStore(s Store) {
	if s == nil {
		s = NoopStore{}
	}
	g.store = s
}

// SetWireAdmitter installs the per-org client IP gate (defaults to NoopWireAdmitter).
func (g *Gateway) SetWireAdmitter(a WireAdmitter) {
	if a == nil {
		a = NoopWireAdmitter{}
	}
	g.admitter = a
}

// SetRequireOrgID requires agents to register with a non-empty organization_id and rejects client
// relays when the serving agent omitted it (production default when a control plane is configured).
func (g *Gateway) SetRequireOrgID(v bool) {
	g.requireOrgID = v
}

// SetConnRateLimiter installs per-IP / per-org new-connection limits (defaults to unlimited).
func (g *Gateway) SetConnRateLimiter(l ConnRateLimiter) {
	if l == nil {
		l = NoopConnRateLimiter{}
	}
	g.connLimiter = l
}

// ListenAgents accepts agent (egress) connections until ctx is cancelled. Pass a tls.Config-wrapped
// listener for mTLS in production.
func (g *Gateway) ListenAgents(ctx context.Context, ln net.Listener) error {
	go closeOnDone(ctx, ln)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			if err := g.ServeAgent(conn); err != nil {
				g.log.Printf("agent session ended: %v", err)
			}
		}()
	}
}

// ServeAgent handles one agent connection: register, then track liveness until it disconnects.
func (g *Gateway) ServeAgent(conn net.Conn) error {
	sess := tunnel.Server(conn)
	defer sess.Close()

	reg, err := sess.NextControl()
	if err != nil {
		return err
	}
	if reg.Kind != tunnel.KindRegister {
		_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "expected register"})
		return errors.New("gateway: first control was not register")
	}
	if g.authToken != "" && reg.Token != g.authToken {
		_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "unauthorized"})
		return errors.New("gateway: agent failed authentication")
	}
	if reg.AgentID == "" {
		_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "missing agent_id"})
		return errors.New("gateway: agent missing id")
	}
	if g.requireOrgID && strings.TrimSpace(reg.OrgID) == "" {
		_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "missing organization_id"})
		return ErrMissingOrgID
	}

	ac := &agentConn{id: reg.AgentID, orgID: reg.OrgID, sess: sess, targets: reg.Targets}
	g.register(ac)
	defer g.deregister(ac)

	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: true}); err != nil {
		return err
	}
	g.log.Printf("agent %q registered with %d target(s)", ac.id, len(ac.targets))

	for {
		if _, err := sess.NextControl(); err != nil {
			return err
		}
		// heartbeats (and future control messages) keep the loop alive; the registry stays valid
		// until the session closes and NextControl returns an error.
	}
}

func (g *Gateway) register(ac *agentConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.agents[ac.id] = ac
	for _, t := range ac.targets {
		g.targets[t.Name] = ac
	}
}

func (g *Gateway) deregister(ac *agentConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.agents[ac.id] == ac {
		delete(g.agents, ac.id)
	}
	for _, t := range ac.targets {
		if g.targets[t.Name] == ac {
			delete(g.targets, t.Name)
		}
	}
}

// Targets returns the currently reachable target names (for diagnostics / readiness).
func (g *Gateway) Targets() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.targets))
	for name := range g.targets {
		out = append(out, name)
	}
	return out
}

// Open dials a target through its agent, returning a net.Conn-backed logical stream.
func (g *Gateway) Open(target string) (net.Conn, error) {
	g.mu.RLock()
	ac := g.targets[target]
	g.mu.RUnlock()
	if ac == nil {
		return nil, ErrNoAgent
	}
	return ac.sess.Open(tunnel.OpenMeta{Target: target}.Encode())
}

// ListenClients accepts native-client connections and relays each to target over its agent tunnel.
func (g *Gateway) ListenClients(ctx context.Context, ln net.Listener, target string) error {
	go closeOnDone(ctx, ln)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			if err := g.ServeClient(conn, target); err != nil {
				g.log.Printf("client relay for %q ended: %v", target, err)
			}
		}()
	}
}

// ServeClient relays a single native-client connection to its target's agent tunnel, recording the
// session lifecycle (best-effort) via the configured Store.
func (g *Gateway) ServeClient(client net.Conn, target string) error {
	defer client.Close()

	clientAddr := client.RemoteAddr().String()

	g.mu.RLock()
	ac := g.targets[target]
	g.mu.RUnlock()
	if ac == nil {
		g.logRejectedClient(target, clientAddr, "", ErrNoAgent)
		return ErrNoAgent
	}
	if g.requireOrgID && strings.TrimSpace(ac.orgID) == "" {
		g.logRejectedClient(target, clientAddr, ac.orgID, ErrMissingOrgID)
		return ErrMissingOrgID
	}
	if g.connLimiter != nil {
		if err := g.connLimiter.Allow(clientAddr, ac.orgID); err != nil {
			g.logRejectedClient(target, clientAddr, ac.orgID, err)
			return err
		}
	}
	if g.admitter != nil {
		ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		err := g.admitter.Admit(ctx, ac.orgID, clientAddr, target)
		cancel()
		if err != nil {
			g.logRejectedClient(target, clientAddr, ac.orgID, err)
			return err
		}
	}
	stream, err := ac.sess.Open(tunnel.OpenMeta{Target: target}.Encode())
	if err != nil {
		g.logRejectedClient(target, clientAddr, ac.orgID, err)
		return err
	}
	defer stream.Close()

	binding, _ := ac.target(target)
	rec := SessionRecord{
		AgentID:        ac.id,
		OrgID:          ac.orgID,
		Target:         target,
		DBType:         binding.DBType,
		ClientAddr:     client.RemoteAddr().String(),
		ResourceRoleID: binding.ResourceRoleID,
		ActorEmail:     binding.ActorEmail,
		StartedAt:      time.Now().UTC(),
	}
	sessionID := ""
	if id, serr := g.storeStarted(rec); serr != nil {
		g.log.Printf("session recording (start) failed: %v", serr)
	} else {
		sessionID = id
	}

	// Sniff the DB login username off the (unmasked) client->upstream auth handshake so the control
	// plane can attribute the session to its owner via the matching credential lease.
	sniffer := newLoginUserSniffer(binding.DBType)
	up, down, rerr := relayCounted(client, stream, sniffer)

	res := SessionResult{
		EndedAt:    time.Now().UTC(),
		BytesUp:    up,
		BytesDown:  down,
		Status:     "executed",
		DBUsername: sniffer.username(),
	}
	if rerr != nil {
		res.Status = "cancelled"
		res.Error = rerr.Error()
	}
	if serr := g.storeEnded(sessionID, res); serr != nil {
		g.log.Printf("session recording (end) failed: %v", serr)
	}
	return rerr
}

// logRejectedClient records why a native-client connection was torn down before any bytes were
// relayed. The gateway is a protocol-agnostic raw-TCP relay (it never speaks Postgres/MySQL/Mongo
// wire), so it cannot safely write a driver-specific error response onto the client socket without
// risking corrupting the client's handshake — the client just sees the TCP connection close. This
// at least makes the reason (no agent / missing org / rate limit / admit-denied / tunnel-open
// failure) visible server-side instead of every rejection looking identical.
func (g *Gateway) logRejectedClient(target, clientAddr, orgID string, err error) {
	g.log.Printf("client relay rejected: target=%q client=%q org=%q reason=%v", target, clientAddr, orgID, err)
}

func (g *Gateway) storeStarted(rec SessionRecord) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	return g.store.SessionStarted(ctx, rec)
}

func (g *Gateway) storeEnded(sessionID string, res SessionResult) error {
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	return g.store.SessionEnded(ctx, sessionID, res)
}

// relayCounted copies bytes both ways until either side ends, returning the byte volume per
// direction. up = client->stream (queries), down = stream->client (masked results). clientTap, when
// non-nil, receives a copy of the client->stream bytes (used to sniff the login username); it must
// never block or error.
func relayCounted(client, stream net.Conn, clientTap io.Writer) (up, down int64, err error) {
	var u, d int64
	errc := make(chan error, 2)
	go func() { n, e := io.Copy(stream, tapReader(client, clientTap)); atomic.StoreInt64(&u, n); errc <- e }()
	go func() { n, e := io.Copy(client, stream); atomic.StoreInt64(&d, n); errc <- e }()
	e := <-errc
	_ = client.Close()
	_ = stream.Close()
	<-errc
	if errors.Is(e, io.EOF) || errors.Is(e, net.ErrClosed) {
		e = nil
	}
	return atomic.LoadInt64(&u), atomic.LoadInt64(&d), e
}

func closeOnDone(ctx context.Context, ln net.Listener) {
	<-ctx.Done()
	_ = ln.Close()
}
