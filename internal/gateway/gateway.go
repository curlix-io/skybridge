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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wiremtls"
)

// ErrNoAgent is returned when no registered agent can serve a requested target.
var ErrNoAgent = errors.New("gateway: no agent registered for target")

// ErrMissingOrgID is returned when an agent or relay path lacks organization_id.
var ErrMissingOrgID = errors.New("gateway: missing organization_id")

const storeTimeout = 5 * time.Second

// Gateway holds the live agent registry and relays client connections over agent tunnels.
type Gateway struct {
	authToken    string
	log          *slog.Logger
	store        Store
	admitter     WireAdmitter
	resolver     TargetResolver
	requireOrgID bool
	connLimiter  ConnRateLimiter

	mu        sync.RWMutex
	agents    map[string]*agentConn // agent id -> connection
	orgAgents map[string]*agentConn // org id -> serving agent (one agent process per org)
}

type agentConn struct {
	id    string
	orgID string
	sess  *tunnel.Session
}

// New creates a Gateway. authToken (if non-empty) is required from agents at registration.
func New(authToken string, logger *slog.Logger) *Gateway {
	if logger == nil {
		logger = slog.Default()
	}
	return &Gateway{
		authToken:   authToken,
		log:         logger,
		store:       NoopStore{},
		admitter:    NoopWireAdmitter{},
		resolver:    NoopTargetResolver{},
		connLimiter: NoopConnRateLimiter{},
		agents:      make(map[string]*agentConn),
		orgAgents:   make(map[string]*agentConn),
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

// SetTargetResolver installs the per-connection target resolver (defaults to NoopTargetResolver,
// which fails closed — there is no safe default target to relay to without a control plane).
func (g *Gateway) SetTargetResolver(r TargetResolver) {
	if r == nil {
		r = NoopTargetResolver{}
	}
	g.resolver = r
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
				g.log.Warn(fmt.Sprintf("agent session ended: %v", err))
			}
		}()
	}
}

// ServeAgent handles one agent connection: register, then track liveness until it disconnects. When
// conn is a *tls.Conn with a verified client cert (the gateway's agent listener wraps ln in a
// wiremtls.ServerConfig-based tls.Config), the cert's SPIFFE identity is authoritative and the
// plaintext bearer token check is skipped entirely — mirrors the connector gateway's mTLS-vs-bearer
// dual mode.
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

	certTenant, certAgentID, mtlsVerified := peerWireIdentity(conn)
	if mtlsVerified {
		if reg.OrgID != "" && reg.OrgID != certTenant {
			_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "org_id does not match client certificate"})
			return errors.New("gateway: agent org_id does not match client certificate")
		}
		if reg.AgentID != "" && reg.AgentID != certAgentID {
			_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "agent_id does not match client certificate"})
			return errors.New("gateway: agent agent_id does not match client certificate")
		}
		reg.OrgID = certTenant
		reg.AgentID = certAgentID
	} else if g.authToken != "" && reg.Token != g.authToken {
		_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "unauthorized"})
		return errors.New("gateway: agent failed authentication")
	}
	if reg.AgentID == "" {
		_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "missing agent_id"})
		return errors.New("gateway: agent missing id")
	}
	if (g.requireOrgID || g.resolverIsLive()) && strings.TrimSpace(reg.OrgID) == "" {
		_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "missing organization_id"})
		return ErrMissingOrgID
	}

	ac := &agentConn{id: reg.AgentID, orgID: reg.OrgID, sess: sess}
	g.register(ac)
	defer g.deregister(ac)

	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: true}); err != nil {
		return err
	}
	g.log.Info(fmt.Sprintf("agent %q registered (org=%q)", ac.id, ac.orgID))

	// The agent's readLoop enforces tunnel.IdleTimeout waiting for ANY frame; without a gateway-side
	// heartbeat, an agent with no active client relays would see nothing but its own outbound
	// heartbeats and could sit fine — but a truly idle gateway->agent direction (no client streams
	// opened) still needs a periodic frame so the agent's deadline never starves. Mirrors agent.go's
	// heartbeatLoop so both directions detect an ungracefully-killed peer within IdleTimeout.
	go agentHeartbeatLoop(sess)

	for {
		ctrl, err := sess.NextControl()
		if err != nil {
			return err
		}
		if ctrl.Kind == tunnel.KindTranscript {
			g.handleTranscript(ac, ctrl)
		}
		// heartbeats (and other control messages) otherwise just keep the loop alive; the registry
		// stays valid until the session closes and NextControl returns an error.
	}
}

// handleTranscript relays one agent-flushed session-replay transcript batch to the control plane
// (best-effort, same posture as storeStarted/storeEnded — a recording failure must never affect
// the live relay, which has already completed by the time a transcript arrives).
func (g *Gateway) handleTranscript(ac *agentConn, ctrl tunnel.Control) {
	if strings.TrimSpace(ctrl.SessionID) == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), storeTimeout)
	defer cancel()
	chunks := TranscriptChunks{OrgID: ac.orgID, Chunks: ctrl.TranscriptChunks, Truncated: ctrl.Truncated}
	if err := g.store.SessionTranscript(ctx, ctrl.SessionID, chunks); err != nil {
		g.log.Warn(fmt.Sprintf("session transcript recording failed session=%q: %v", ctrl.SessionID, err))
	}
}

func agentHeartbeatLoop(sess *tunnel.Session) {
	t := time.NewTicker(tunnel.IdleTimeout / 3)
	defer t.Stop()
	for {
		select {
		case <-sess.Closed():
			return
		case <-t.C:
			if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindHeartbeat}); err != nil {
				return
			}
		}
	}
}

func (g *Gateway) register(ac *agentConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.agents[ac.id] = ac
	if ac.orgID != "" {
		g.orgAgents[ac.orgID] = ac
	}
}

func (g *Gateway) deregister(ac *agentConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.agents[ac.id] == ac {
		delete(g.agents, ac.id)
	}
	if ac.orgID != "" && g.orgAgents[ac.orgID] == ac {
		delete(g.orgAgents, ac.orgID)
	}
}

// resolverIsLive reports whether a real (non-Noop) TargetResolver is installed — once it is, org id
// becomes load-bearing for routing (see ServeAgent/ServeClient), not just an optional attribution
// field.
func (g *Gateway) resolverIsLive() bool {
	_, noop := g.resolver.(NoopTargetResolver)
	return !noop
}

// RegisteredOrgs returns the currently connected agents' org ids (for diagnostics / readiness).
func (g *Gateway) RegisteredOrgs() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, 0, len(g.orgAgents))
	for orgID := range g.orgAgents {
		out = append(out, orgID)
	}
	return out
}

// Open resolves a target for orgID through its agent, returning a net.Conn-backed logical stream.
func (g *Gateway) Open(ctx context.Context, orgID, target string) (net.Conn, error) {
	g.mu.RLock()
	ac := g.orgAgents[orgID]
	g.mu.RUnlock()
	if ac == nil {
		return nil, ErrNoAgent
	}
	binding, err := g.resolver.Resolve(ctx, orgID, target)
	if err != nil {
		return nil, err
	}
	return ac.sess.Open(tunnel.OpenMeta{
		Target:         target,
		Addr:           binding.Addr,
		DBType:         binding.DBType,
		ResourceRoleID: binding.ResourceRoleID,
		ActorEmail:     binding.ActorEmail,
	}.Encode())
}

// ListenClients accepts native-client connections and relays each to target over orgID's agent
// tunnel.
func (g *Gateway) ListenClients(ctx context.Context, ln net.Listener, orgID, target string) error {
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
			if err := g.ServeClient(conn, orgID, target); err != nil {
				g.log.Warn(fmt.Sprintf("client relay for org=%q target=%q ended: %v", orgID, target, err))
			}
		}()
	}
}

// ServeClient relays a single native-client connection to orgID's agent tunnel, resolving the
// target's addr/db_type live for this connection and recording the session lifecycle (best-effort)
// via the configured Store.
func (g *Gateway) ServeClient(client net.Conn, orgID, target string) error {
	defer client.Close()

	clientAddr := client.RemoteAddr().String()

	if (g.requireOrgID || g.resolverIsLive()) && strings.TrimSpace(orgID) == "" {
		g.logRejectedClient(target, clientAddr, orgID, ErrMissingOrgID)
		return ErrMissingOrgID
	}
	g.mu.RLock()
	ac := g.orgAgents[orgID]
	g.mu.RUnlock()
	if ac == nil {
		g.logRejectedClient(target, clientAddr, orgID, ErrNoAgent)
		return ErrNoAgent
	}
	if g.connLimiter != nil {
		if err := g.connLimiter.Allow(clientAddr, orgID); err != nil {
			g.logRejectedClient(target, clientAddr, orgID, err)
			return err
		}
	}
	if g.admitter != nil {
		actx, cancel := context.WithTimeout(context.Background(), storeTimeout)
		err := g.admitter.Admit(actx, orgID, clientAddr, target)
		cancel()
		if err != nil {
			g.logRejectedClient(target, clientAddr, orgID, err)
			return err
		}
	}

	rctx, rcancel := context.WithTimeout(context.Background(), storeTimeout)
	binding, err := g.resolver.Resolve(rctx, orgID, target)
	rcancel()
	if err != nil {
		g.logRejectedClient(target, clientAddr, orgID, err)
		return err
	}

	stream, err := ac.sess.Open(tunnel.OpenMeta{
		Target:         target,
		Addr:           binding.Addr,
		DBType:         binding.DBType,
		ResourceRoleID: binding.ResourceRoleID,
		ActorEmail:     binding.ActorEmail,
	}.Encode())
	if err != nil {
		g.logRejectedClient(target, clientAddr, orgID, err)
		return err
	}
	defer stream.Close()

	rec := SessionRecord{
		AgentID:        ac.id,
		OrgID:          orgID,
		Target:         target,
		DBType:         binding.DBType,
		ClientAddr:     client.RemoteAddr().String(),
		ResourceRoleID: binding.ResourceRoleID,
		ActorEmail:     binding.ActorEmail,
		StartedAt:      time.Now().UTC(),
	}
	sessionID := ""
	if id, serr := g.storeStarted(rec); serr != nil {
		g.log.Warn(fmt.Sprintf("session recording (start) failed: %v", serr))
	} else {
		sessionID = id
	}

	// Sniff the DB login username off the (unmasked) client->upstream auth handshake so the control
	// plane can attribute the session to its owner via the matching credential lease.
	sniffer := newLoginUserSniffer(binding.DBType)
	up, down, rerr := relayCounted(client, stream, sniffer)

	res := SessionResult{
		OrgID:      orgID,
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
		g.log.Warn(fmt.Sprintf("session recording (end) failed: %v", serr))
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
	g.log.Warn(fmt.Sprintf("client relay rejected: target=%q client=%q org=%q reason=%v", target, clientAddr, orgID, err))
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

// peerWireIdentity extracts (tenant_id, agent_id) from conn's verified TLS client certificate, when
// conn is a *tls.Conn that completed a handshake with a peer cert (ServerConfig requires and
// verifies one against the wire mTLS CA — a connection reaching here with a peer cert is already
// CA-verified, only the SPIFFE SAN needs parsing). Returns ok=false for plain (non-TLS) connections,
// i.e. the legacy bearer-token tunnel.
func peerWireIdentity(conn net.Conn) (tenant, agentID string, ok bool) {
	tconn, isTLS := conn.(*tls.Conn)
	if !isTLS {
		return "", "", false
	}
	state := tconn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", "", false
	}
	return wiremtls.IdentityFromCert(state.PeerCertificates[0])
}
