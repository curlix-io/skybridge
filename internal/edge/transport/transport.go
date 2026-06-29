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
	"io"
	"log"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	agentv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/agent/v1"
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"

	"github.com/curlix-io/skybridge/internal/edge"
)

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

	// mTLS (hardened path). When CABundlePEM is empty and TLSDir is unset, the client uses bearer.
	CABundlePEM  []byte // CA bundle trusted for the gateway (enables mTLS)
	TLSDir       string // directory holding/persisting ca.pem, client.crt, client.key
	EnrollTarget string // Enroll endpoint host:port (defaults to Target)
	EnrollToken  string // one-time enrollment token (needed to obtain the first cert)
	TrustDomain  string // SPIFFE trust domain placed in the CSR SAN (cosmetic; default skybridge.edge)
}

// Client maintains the call-home connection and serves dispatched tool work.
type Client struct {
	cfg    Config
	reg    *edge.Registry
	logger *log.Logger

	mu   sync.Mutex
	runs map[string]context.CancelFunc
}

// New builds a call-home client. reg supplies the edge-handled tools.
func New(cfg Config, reg *edge.Registry, logger *log.Logger) *Client {
	if logger == nil {
		logger = log.Default()
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 30 * time.Second
	}
	return &Client{cfg: cfg, reg: reg, logger: logger, runs: map[string]context.CancelFunc{}}
}

// Run dials the gateway and serves work, reconnecting with backoff until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		material, err := c.ensureTLSMaterial(ctx)
		if err != nil {
			return err // fatal config error (e.g. CA present but no cert and no enroll token)
		}
		conn, derr := c.dial(material)
		if derr == nil {
			serveErr := c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), material == nil)
			_ = conn.Close()
			if serveErr != nil {
				c.logger.Printf("skybridge-edge: call-home stream ended: %v", serveErr)
			}
			backoff = time.Second
		} else {
			c.logger.Printf("skybridge-edge: dial %s failed: %v", c.cfg.Target, derr)
		}
		if !c.cfg.Reconnect {
			return derr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > c.cfg.MaxBackoff {
			backoff = c.cfg.MaxBackoff
		}
	}
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
	return grpc.NewClient(c.cfg.Target, grpc.WithTransportCredentials(creds))
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
			c.logger.Printf("skybridge-edge: registered session=%s tenant=%s", m.Registered.GetSessionId(), c.cfg.TenantID)
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
