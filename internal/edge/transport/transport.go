// Package transport is the edge's egress-only call-home client. It dials OUT to the SaaS Connector
// Gateway, registers for its tenant, and serves dispatched single-tool calls by running them through
// the edge registry and streaming results back over the same stream. It is the Go counterpart of the
// Python connector/agent.py "connect" path, scoped to the edge's role: run one read-only tool per
// assignment (no local LLM loop).
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	agentv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/agent/v1"
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"

	"github.com/curlix-io/skybridge/internal/edge"
)

// jitteredBackoff returns a random duration in [d/2, d) so many edges losing the same gateway at
// once don't all reconnect in lockstep (thundering herd).
func jitteredBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half+1)))
}

// backoffResetAfter: only reset backoff to baseline (1s) if the prior connection actually stayed
// up this long. Without this, a connect-then-immediately-drop cycle (bad keepalive, a listener
// flapping) resets to a 0-delay retry every single cycle -- a tight loop that never actually
// backs off. Matches hoop.dev's own agent/main.go heuristic (defaultBackoffResetSec, same value,
// same reasoning) -- see docs/design/skybridge-masking-architecture.md §10.3 in curlix/curlix.
var backoffResetAfter = 60 * time.Second

// authFailureBackoffFloor: an auth failure (expired/revoked credential) is a config problem, not
// a transient network blip -- a fleet sharing one standing credential that hits its TTL boundary
// at the same moment would otherwise retry in near-lockstep every ordinary backoff step forever.
// Mirrors curlix.connector.agent._AUTH_FAILURE_BACKOFF_FLOOR_SECONDS in the Python reference.
var authFailureBackoffFloor = 120 * time.Second

// preConnectTimeout bounds the advisory PreConnect unary call so a hung gateway can't stall the
// reconnect loop; on any error (older gateway that doesn't implement it, timeout, dial failure)
// the caller falls back to attempting Connect directly.
var preConnectTimeout = 10 * time.Second

// Version reported to the gateway on Register.
const Version = "0.1.0"

// Config is the call-home client configuration. When a CA bundle (and optionally an enrollment
// token) is supplied the client uses mTLS — calling Enroll to obtain a client cert, then Connect
// with it; otherwise it falls back to bearer-token-over-TLS.
type Config struct {
	Target      string        // gateway Connect endpoint host:port (dialed OUT)
	TenantID    string        // organization id this edge serves
	ConnectorID string        // stable edge instance id
	Token       string        // bearer token (when not using mTLS)
	Insecure    bool          // plaintext channel (dev only; ignored when mTLS material is present)
	Reconnect   bool          // reconnect with backoff on stream loss
	MaxBackoff  time.Duration // cap for reconnect backoff (default 30s)

	// gRPC keepalive: detects a dead/killed gateway (crash, ECS task replacement) without waiting
	// on OS TCP keepalive (hours) or an incidental LB idle-timeout reset. Must stay in lockstep with
	// whatever server-side keepalive policy the gateway enforces — KeepaliveTime here should stay
	// above the server's minimum ping interval without data, or healthy pings risk an
	// ENHANCE_YOUR_CALM.
	KeepaliveTime    time.Duration // ping interval when the stream is idle (default 20s)
	KeepaliveTimeout time.Duration // time to wait for a ping ack before declaring the peer dead (default 10s)

	// mTLS (hardened path). When CABundlePEM is empty and TLSDir is unset, the client uses bearer.
	CABundlePEM []byte // CA bundle trusted for the gateway (enables mTLS)
	TLSDir      string // directory holding/persisting ca.pem, client.crt, client.key
	// IdentitySecretARN, when set, mirrors the issued cert to this AWS Secrets Manager secret so a
	// replaced task (fresh disk) recovers its identity instead of re-enrolling with an already-used
	// one-time token. See SKYBRIDGE_IDENTITY_SECRET_ARN.
	IdentitySecretARN string
	EnrollTarget      string // Enroll endpoint host:port (defaults to Target)
	EnrollToken       string // one-time enrollment token (needed to obtain the first cert)
	TrustDomain       string // SPIFFE trust domain placed in the CSR SAN (cosmetic; default skybridge.edge)

	// IamAuthEnabled, when true, mints its own enroll token by presigning sts:GetCallerIdentity
	// with the edge's ambient AWS credentials (an ECS task role, in production) instead of relying
	// on a static, single-use EnrollToken — see internal/edgeiam. Safe to use on every restart,
	// including a redeployed task with a wiped disk. IamEnrollURL is the control-plane HTTPS
	// origin that verifies the presigned request (see SKYBRIDGE_IAM_AUTH / SKYBRIDGE_IAM_ENROLL_URL).
	IamAuthEnabled bool
	IamEnrollURL   string
}

// Client maintains the call-home connection and serves dispatched tool work.
type Client struct {
	cfg    Config
	reg    *edge.Registry
	logger *slog.Logger

	mu   sync.Mutex
	runs map[string]context.CancelFunc
}

// New builds a call-home client. reg supplies the edge-handled tools.
func New(cfg Config, reg *edge.Registry, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	if cfg.KeepaliveTime <= 0 {
		cfg.KeepaliveTime = 20 * time.Second
	}
	if cfg.KeepaliveTimeout <= 0 {
		cfg.KeepaliveTimeout = 10 * time.Second
	}
	return &Client{cfg: cfg, reg: reg, logger: logger, runs: map[string]context.CancelFunc{}}
}

// proactiveRenewalSkew is how far ahead of expiry a proactive renewal kicks in -- deliberately
// much wider than certRenewSkew (the "still usable to connect" check in ensureTLSMaterial), since
// this loop runs independently of the Connect stream's lifecycle and only gets one attempt per
// proactiveRenewalCheckInterval.
var proactiveRenewalSkew = 24 * time.Hour

// proactiveRenewalCheckInterval is how often the renewal loop wakes up to check cert expiry.
// Renewal isn't on the hot path and a missed check just gets retried later, so this is coarse.
var proactiveRenewalCheckInterval = time.Hour

// renewalLoop runs for the lifetime of Run, independent of the Connect stream's own reconnect
// cycle: a long-lived process that never drops its stream would otherwise ride renew-on-drop-only
// all the way to expiry with nothing to trigger a refresh. See docs/design/
// skybridge-masking-architecture.md §10.8 in curlix/curlix. No-ops in bearer mode.
func (c *Client) renewalLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitteredBackoff(proactiveRenewalCheckInterval)):
		}
		material, err := c.ensureTLSMaterial(ctx)
		if err != nil || material == nil {
			continue // bearer mode, or a transient load/enroll error -- try again next tick
		}
		if certValid(material.clientCertPEM, proactiveRenewalSkew) {
			continue // not yet within the renewal window
		}
		if _, err := c.renewCert(ctx, material); err != nil {
			c.logger.Warn(fmt.Sprintf("proactive cert renewal failed: %v", err))
			continue
		}
		c.logger.Info("cert proactively renewed")
	}
}

// Run dials the gateway and serves work, reconnecting with backoff until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	go c.renewalLoop(ctx)
	backoff := time.Second
	for {
		material, err := c.ensureTLSMaterial(ctx)
		if err != nil {
			return err // fatal config error (e.g. CA present but no cert and no enroll token)
		}
		conn, derr := c.dial(material)
		authFailure := false
		if derr == nil {
			client := connectorv1.NewConnectorGatewayClient(conn)
			useBearer := material == nil
			ok, retryAfter, reason := c.preConnect(ctx, client, useBearer)
			if !ok {
				_ = conn.Close()
				c.logger.Info(fmt.Sprintf("pre-connect: gateway says wait (%s), retrying in ~%s", reason, retryAfter))
				if !c.cfg.Reconnect {
					return nil
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(jitteredBackoff(retryAfter)):
				}
				continue // don't touch the reconnect backoff state -- this wasn't a failure
			}

			started := time.Now()
			serveErr := c.serve(ctx, client, useBearer)
			_ = conn.Close()
			authFailure = status.Code(serveErr) == codes.Unauthenticated
			switch {
			case authFailure:
				c.logger.Error(fmt.Sprintf(
					"call-home authentication rejected (credential expired or revoked?) -- this "+
						"edge needs a fresh enrollment/bearer credential; will keep retrying at a "+
						"reduced rate: %v", serveErr))
			case serveErr != nil:
				c.logger.Warn(fmt.Sprintf("call-home stream ended: %v", serveErr))
			case time.Since(started) >= backoffResetAfter:
				backoff = time.Second // clean close of a connection that was actually stable
			}
		} else {
			c.logger.Warn(fmt.Sprintf("dial %s failed: %v", c.cfg.Target, derr))
		}
		if !c.cfg.Reconnect {
			return derr
		}
		sleepFor := backoff
		if authFailure && sleepFor < authFailureBackoffFloor {
			sleepFor = authFailureBackoffFloor
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitteredBackoff(sleepFor)):
		}
		if backoff *= 2; backoff > c.cfg.MaxBackoff {
			backoff = c.cfg.MaxBackoff
		}
	}
}

// preConnect is a best-effort admission check before opening the full Connect stream, so the
// gateway can say "not yet" (draining, rate-limited, revoked) without this client paying for a
// full stream handshake first. Any error (older gateway that doesn't implement this RPC yet,
// timeout) is treated as "proceed" -- this is advisory, never a hard gate. See
// docs/design/skybridge-masking-architecture.md §10.3 in curlix/curlix.
func (c *Client) preConnect(ctx context.Context, client connectorv1.ConnectorGatewayClient, useBearer bool) (ok bool, retryAfter time.Duration, reason string) {
	callCtx, cancel := context.WithTimeout(ctx, preConnectTimeout)
	defer cancel()
	if useBearer && c.cfg.Token != "" {
		callCtx = metadata.NewOutgoingContext(callCtx, metadata.Pairs("authorization", "Bearer "+c.cfg.Token))
	}
	resp, err := client.PreConnect(callCtx, &connectorv1.PreConnectRequest{
		TenantId:    c.cfg.TenantID,
		ConnectorId: c.cfg.ConnectorID,
	})
	if err != nil {
		c.logger.Debug(fmt.Sprintf("pre-connect check skipped: %v", err))
		return true, 0, ""
	}
	if resp.GetOk() {
		return true, 0, ""
	}
	wait := time.Duration(resp.GetRetryAfterSeconds()) * time.Second
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait, resp.GetReason()
}

func (c *Client) dial(material *tlsMaterial) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	switch {
	case material != nil:
		tlsCfg, err := mtlsTLSConfig(material)
		if err != nil {
			return nil, err
		}
		creds = credentials.NewTLS(tlsCfg)
	case c.cfg.Insecure:
		creds = insecure.NewCredentials()
	default:
		creds = credentials.NewTLS(nil) // system roots
	}
	return grpc.NewClient(c.cfg.Target,
		grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                c.cfg.KeepaliveTime,
			Timeout:             c.cfg.KeepaliveTimeout,
			PermitWithoutStream: true, // Connect is a single long-lived, often-idle stream
		}),
	)
}

// serve runs one Connect stream: register, then handle gateway messages until the stream ends. When
// useBearer is true (no mTLS material) the bearer token is attached as call metadata.
func (c *Client) serve(ctx context.Context, client connectorv1.ConnectorGatewayClient, useBearer bool) error {
	if useBearer && c.cfg.Token != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+c.cfg.Token))
	}
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	ss := &safeStream{stream: stream}

	if err := ss.send(&connectorv1.ConnectorMessage{
		Msg: &connectorv1.ConnectorMessage_Register{Register: &connectorv1.Register{
			TenantId:    c.cfg.TenantID,
			ConnectorId: c.cfg.ConnectorID,
			Version:     Version,
		}},
	}); err != nil {
		return err
	}

	for {
		gmsg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch m := gmsg.Msg.(type) {
		case *connectorv1.GatewayMessage_Registered:
			c.logger.Info(fmt.Sprintf("registered session=%s tenant=%s", m.Registered.GetSessionId(), c.cfg.TenantID))
		case *connectorv1.GatewayMessage_WorkAssignment:
			c.startWork(ctx, ss, m.WorkAssignment)
		case *connectorv1.GatewayMessage_CancelWork:
			c.cancelWork(m.CancelWork.GetRunId())
		case *connectorv1.GatewayMessage_Ping:
			_ = ss.send(&connectorv1.ConnectorMessage{
				Msg: &connectorv1.ConnectorMessage_Heartbeat{Heartbeat: &connectorv1.Heartbeat{UnixMillis: time.Now().UnixMilli()}},
			})
		}
	}
}

func (c *Client) startWork(parent context.Context, ss *safeStream, wa *connectorv1.WorkAssignment) {
	runID := wa.GetRunId()
	if runID == "" {
		return
	}
	runCtx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	if _, exists := c.runs[runID]; exists {
		c.mu.Unlock()
		cancel()
		return
	}
	c.runs[runID] = cancel
	c.mu.Unlock()

	go func() {
		defer c.finishRun(runID)
		c.handleWork(runCtx, ss, runID, wa)
	}()
}

func (c *Client) finishRun(runID string) {
	c.mu.Lock()
	if cancel, ok := c.runs[runID]; ok {
		cancel()
		delete(c.runs, runID)
	}
	c.mu.Unlock()
}

func (c *Client) cancelWork(runID string) {
	c.mu.Lock()
	cancel := c.runs[runID]
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// handleWork decodes the single-tool envelope from the run goal, dispatches it locally, and streams
// back a ToolResult + terminal RunFinished. The edge only runs single read-only tools; a plain
// natural-language goal (full agent run) is not something the edge executes.
func (c *Client) handleWork(ctx context.Context, ss *safeStream, runID string, wa *connectorv1.WorkAssignment) {
	goal := wa.GetStart().GetGoal()
	call, ok := edge.DecodeToolRequest(goal)
	if !ok {
		c.emitFinished(ss, runID, "error", "edge executes single read-only tool calls only")
		return
	}
	res := c.reg.Dispatch(ctx, call)
	okBool, _ := res["ok"].(bool)
	errStr, _ := res["error"].(string)
	out, err := json.Marshal(res)
	if err != nil {
		out = []byte("{}")
	}
	c.emit(ss, runID, &agentv1.AgentEvent{Event: &agentv1.AgentEvent_ToolResult{ToolResult: &agentv1.ToolResult{
		Step:       0,
		Ok:         okBool,
		Name:       call.Name,
		OutputJson: string(out),
		Error:      errStr,
	}}})
	if okBool {
		c.emitFinished(ss, runID, "final_answer", "")
	} else {
		c.emitFinished(ss, runID, "error", errStr)
	}
}

func (c *Client) emit(ss *safeStream, runID string, ev *agentv1.AgentEvent) {
	_ = ss.send(&connectorv1.ConnectorMessage{
		Msg: &connectorv1.ConnectorMessage_WorkEvent{WorkEvent: &connectorv1.WorkEvent{RunId: runID, Event: ev}},
	})
}

func (c *Client) emitFinished(ss *safeStream, runID, stoppedReason, errDetail string) {
	resp := map[string]any{
		"final_answer":   "",
		"source":         "",
		"steps":          []any{},
		"stopped_reason": stoppedReason,
	}
	if errDetail != "" {
		resp["error_detail"] = errDetail
	}
	b, _ := json.Marshal(resp)
	c.emit(ss, runID, &agentv1.AgentEvent{Event: &agentv1.AgentEvent_Finished{Finished: &agentv1.RunFinished{ResponseJson: string(b)}}})
}

// safeStream serializes Send across goroutines (grpc-go forbids concurrent SendMsg on one stream).
type safeStream struct {
	mu     sync.Mutex
	stream grpc.BidiStreamingClient[connectorv1.ConnectorMessage, connectorv1.GatewayMessage]
}

func (s *safeStream) send(m *connectorv1.ConnectorMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(m)
}
