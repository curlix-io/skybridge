package studiotransport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/curlix-io/skybridge/internal/edge/dbquery"
	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
	"github.com/curlix-io/skybridge/internal/mask"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// jitteredBackoff returns a random duration in [d/2, d) so many edges losing the same Studio
// Gateway at once don't all reconnect in lockstep (thundering herd).
func jitteredBackoff(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half+1)))
}

const Version = "0.2.0"

type tlsMaterial struct {
	caBundlePEM   []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

// Config is the Studio Gateway call-home client configuration.
type Config struct {
	Target     string
	TenantID   string
	AgentID    string
	Token      string
	Insecure   bool
	Reconnect  bool
	MaxBackoff time.Duration

	// gRPC keepalive: detects a dead/killed Studio Gateway (crash, task replacement) without
	// waiting on OS TCP keepalive or an incidental LB idle-timeout reset. Mirrors
	// internal/edge/transport.Config's fields — keep both in sync with the gateway's server-side
	// keepalive policy.
	KeepaliveTime    time.Duration // ping interval when the stream is idle (default 20s)
	KeepaliveTimeout time.Duration // time to wait for a ping ack before declaring the peer dead (default 10s)

	MaxSessions int
	Targets     []Target
	DBUser      string // fallback when target.user empty
	DBPassword  string // fallback when target.password empty
	Masker      mask.Masker
	CABundlePEM []byte
	TLSDir      string
	// IdentitySecretARN, when set, mirrors the issued cert to this AWS Secrets Manager secret so a
	// replaced task (fresh disk) recovers its identity instead of re-enrolling with an already-used
	// one-time token. See SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN.
	IdentitySecretARN string
	EnrollTarget      string
	EnrollToken       string
	TrustDomain       string
}

// Client maintains the Studio Gateway Connect stream.
type Client struct {
	cfg    Config
	logger *slog.Logger
	mu     sync.Mutex
	runs   map[string]context.CancelFunc
}

func New(cfg Config, logger *slog.Logger) *Client {
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
	if cfg.AgentID == "" {
		cfg.AgentID = "studio-agent"
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 8
	}
	return &Client{cfg: cfg, logger: logger, runs: map[string]context.CancelFunc{}}
}

func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		material, err := c.ensureTLSMaterial(ctx)
		if err != nil {
			return err
		}
		conn, derr := c.dial(material)
		if derr == nil {
			serveErr := c.serve(ctx, studiov1.NewStudioGatewayClient(conn), material == nil)
			_ = conn.Close()
			if serveErr != nil {
				c.logger.Warn(fmt.Sprintf("studio call-home ended: %v", serveErr))
			}
			backoff = time.Second
		} else {
			c.logger.Warn(fmt.Sprintf("studio dial %s failed: %v", c.cfg.Target, derr))
		}
		if !c.cfg.Reconnect {
			return derr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitteredBackoff(backoff)):
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
		creds = credentials.NewTLS(nil)
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

func (c *Client) serve(ctx context.Context, client studiov1.StudioGatewayClient, useBearer bool) error {
	if useBearer && c.cfg.Token != "" {
		ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+c.cfg.Token))
	}
	stream, err := client.Connect(ctx)
	if err != nil {
		return err
	}
	ss := &safeStream{stream: stream}

	bindings := make([]*studiov1.TargetBinding, 0, len(c.cfg.Targets))
	for _, t := range c.cfg.Targets {
		bindings = append(bindings, &studiov1.TargetBinding{
			DbType:       t.DBType,
			AwsAccountId: t.AWSAccountID,
			DatabaseName: t.DatabaseName,
		})
	}
	if err := ss.send(&studiov1.AgentMessage{
		Msg: &studiov1.AgentMessage_Register{Register: &studiov1.Register{
			TenantId:    c.cfg.TenantID,
			AgentId:     c.cfg.AgentID,
			Version:     Version,
			Targets:     bindings,
			MaxSessions: int32(c.cfg.MaxSessions),
		}},
	}); err != nil {
		return err
	}

	go c.heartbeatLoop(ctx, ss)

	for {
		gmsg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch m := gmsg.Msg.(type) {
		case *studiov1.GatewayMessage_Registered:
			c.logger.Info(fmt.Sprintf("studio registered lease=%s tenant=%s", m.Registered.GetLeaseId(), c.cfg.TenantID))
		case *studiov1.GatewayMessage_ExecuteAssignment:
			c.startAssignment(ctx, ss, m.ExecuteAssignment)
		case *studiov1.GatewayMessage_CancelSession:
			c.cancelSession(m.CancelSession.GetSessionId())
		case *studiov1.GatewayMessage_Ping:
			_ = ss.send(&studiov1.AgentMessage{
				Msg: &studiov1.AgentMessage_Heartbeat{Heartbeat: &studiov1.Heartbeat{
					UnixMillis:     time.Now().UnixMilli(),
					ActiveSessions: int32(c.activeSessions()),
				}},
			})
		}
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, ss *safeStream) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = ss.send(&studiov1.AgentMessage{
				Msg: &studiov1.AgentMessage_Heartbeat{Heartbeat: &studiov1.Heartbeat{
					UnixMillis:     time.Now().UnixMilli(),
					ActiveSessions: int32(c.activeSessions()),
				}},
			})
		}
	}
}

func (c *Client) activeSessions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.runs)
}

func (c *Client) startAssignment(parent context.Context, ss *safeStream, assign *studiov1.ExecuteAssignment) {
	sessionID := assign.GetSessionId()
	if sessionID == "" {
		return
	}
	if c.activeSessions() >= c.cfg.MaxSessions {
		_ = ss.send(&studiov1.AgentMessage{
			Msg: &studiov1.AgentMessage_SessionAck{SessionAck: &studiov1.SessionAck{
				SessionId: sessionID, Accepted: false, Reason: "agent_at_capacity",
			}},
		})
		return
	}
	runCtx, cancel := context.WithCancel(parent)
	c.mu.Lock()
	if _, exists := c.runs[sessionID]; exists {
		c.mu.Unlock()
		cancel()
		return
	}
	c.runs[sessionID] = cancel
	c.mu.Unlock()

	go func() {
		defer c.finishSession(sessionID)
		c.handleAssignment(runCtx, ss, assign)
	}()
}

func (c *Client) finishSession(sessionID string) {
	c.mu.Lock()
	if cancel, ok := c.runs[sessionID]; ok {
		cancel()
		delete(c.runs, sessionID)
	}
	c.mu.Unlock()
}

func (c *Client) cancelSession(sessionID string) {
	c.mu.Lock()
	cancel := c.runs[sessionID]
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (c *Client) handleAssignment(ctx context.Context, ss *safeStream, assign *studiov1.ExecuteAssignment) {
	sessionID := assign.GetSessionId()
	req := assign.GetRequest()
	_ = ss.send(&studiov1.AgentMessage{
		Msg: &studiov1.AgentMessage_SessionAck{SessionAck: &studiov1.SessionAck{
			SessionId: sessionID, Accepted: true,
		}},
	})
	c.emitEvent(ss, sessionID, &studiov1.ExecuteEvent{
		Event: &studiov1.ExecuteEvent_Started{Started: &studiov1.SessionStarted{StartedUnixMillis: time.Now().UnixMilli()}},
	})

	if req.GetDryRun() {
		payload, _ := json.Marshal(map[string]any{"status": "dry_run", "message": "validated locally"})
		c.emitEvent(ss, sessionID, &studiov1.ExecuteEvent{
			Event: &studiov1.ExecuteEvent_Finished{Finished: &studiov1.ResultFinished{ResponseJson: string(payload)}},
		})
		return
	}

	result, err := c.executeLocally(ctx, req)
	if err != nil {
		c.emitEvent(ss, sessionID, &studiov1.ExecuteEvent{
			Event: &studiov1.ExecuteEvent_Error{Error: &studiov1.ExecuteError{
				Code: "execute_error", Message: err.Error(),
			}},
		})
		return
	}
	payload, err := json.Marshal(result)
	if err != nil {
		c.emitEvent(ss, sessionID, &studiov1.ExecuteEvent{
			Event: &studiov1.ExecuteEvent_Error{Error: &studiov1.ExecuteError{
				Code: "encode_error", Message: err.Error(),
			}},
		})
		return
	}
	c.emitEvent(ss, sessionID, &studiov1.ExecuteEvent{
		Event: &studiov1.ExecuteEvent_Finished{Finished: &studiov1.ResultFinished{ResponseJson: string(payload)}},
	})
}

func (c *Client) emitEvent(ss *safeStream, sessionID string, ev *studiov1.ExecuteEvent) {
	_ = ss.send(&studiov1.AgentMessage{
		Msg: &studiov1.AgentMessage_SessionEvent{SessionEvent: &studiov1.SessionEvent{
			SessionId: sessionID,
			Event:     ev,
		}},
	})
}

func (c *Client) executeLocally(ctx context.Context, req *studiov1.ExecuteRequest) (map[string]any, error) {
	dbType := strings.ToLower(strings.TrimSpace(req.GetDbType()))
	if dbType == "" {
		dbType = "postgres"
	}
	target, ok := dbquery.Resolve(c.cfg.Targets, dbType, req.GetAwsAccountId(), req.GetDatabaseName())
	if !ok {
		return nil, fmt.Errorf("no local target binding for %s/%s/%s", dbType, req.GetAwsAccountId(), req.GetDatabaseName())
	}
	return dbquery.Execute(ctx, target, dbType, req.GetDatabaseName(), req.GetQueryContent(), dbquery.Options{
		FallbackUser:     c.cfg.DBUser,
		FallbackPassword: c.cfg.DBPassword,
		Masker:           c.cfg.Masker,
		ApplyPII:         req.GetApplyPiiRedaction(),
		MaxRows:          1000,
		EnforceReadOnly:  true,
		OrgID:            c.cfg.TenantID,
	})
}

type safeStream struct {
	mu     sync.Mutex
	stream grpc.BidiStreamingClient[studiov1.AgentMessage, studiov1.GatewayMessage]
}

func (s *safeStream) send(m *studiov1.AgentMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(m)
}
