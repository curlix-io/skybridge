package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire"
)

// httpTranscriptRecorder is RunListener/RunK8sAPIListener's counterpart to transcriptRecorder
// (transcript.go): those two modes have no gateway-assigned control-plane session id or open
// tunnel.Session to flush a transcript over (see config.Agent.SessionReplayEnabled's doc) —
// docs/design/kubernetes-access-broker.md §11.7 closes that gap by having the connection mint its
// own local session id and flush via one authenticated HTTP POST instead of a tunnel control
// message. Buffering/truncation semantics mirror transcriptRecorder exactly; only the transport
// differs.
type httpTranscriptRecorder struct {
	sessionID string
	orgID     string
	driver    string
	reportURL string
	token     string
	maxBytes  int

	mu        sync.Mutex
	chunks    []tunnel.TranscriptChunk
	totalSize int
	truncated bool
}

// newHTTPTranscriptRecorder returns a live recorder when replay is enabled and a report URL is
// configured, or wire.NoopRecorder{} otherwise — same opt-in posture as newTranscriptRecorder.
func newHTTPTranscriptRecorder(cfg config.Agent, driver string) wire.Recorder {
	url := strings.TrimSpace(cfg.SessionTranscriptReportURL)
	if !cfg.SessionReplayEnabled || url == "" {
		return wire.NoopRecorder{}
	}
	maxBytes := cfg.SessionReplayMaxBytes
	if maxBytes <= 0 {
		maxBytes = 5 << 20
	}
	return &httpTranscriptRecorder{
		sessionID: newLocalSessionID(),
		orgID:     strings.TrimSpace(cfg.OrgID),
		driver:    driver,
		reportURL: url,
		token:     strings.TrimSpace(cfg.CredentialExchangeToken),
		maxBytes:  maxBytes,
	}
}

func (r *httpTranscriptRecorder) append(direction, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.truncated {
		return
	}
	n := len(text)
	if r.totalSize+n > r.maxBytes {
		r.truncated = true
		return
	}
	r.totalSize += n
	r.chunks = append(r.chunks, tunnel.TranscriptChunk{
		Seq:       len(r.chunks),
		Direction: direction,
		Text:      text,
		Bytes:     n,
	})
}

// RecordInput implements wire.Recorder.
func (r *httpTranscriptRecorder) RecordInput(raw []byte) {
	if len(raw) == 0 {
		return
	}
	r.append("input", string(raw))
}

// RecordOutput implements wire.Recorder.
func (r *httpTranscriptRecorder) RecordOutput(text string) {
	if text == "" {
		return
	}
	r.append("output", text)
}

type httpTranscriptReport struct {
	SessionID        string                   `json:"session_id"`
	OrganizationID   string                   `json:"organization_id"`
	Driver           string                   `json:"driver"`
	TranscriptChunks []tunnel.TranscriptChunk `json:"transcript_chunks"`
	Truncated        bool                     `json:"truncated"`
}

// flushHTTPTranscript is flushTranscript's (transcript.go) HTTP-transport counterpart — best-effort,
// same rationale: a flush failure must never affect the already-completed session.
func flushHTTPTranscript(ctx context.Context, recorder wire.Recorder, logger *slog.Logger) {
	r, ok := recorder.(*httpTranscriptRecorder)
	if !ok {
		return
	}
	r.mu.Lock()
	chunks := r.chunks
	truncated := r.truncated
	r.mu.Unlock()
	if len(chunks) == 0 {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	body, err := json.Marshal(httpTranscriptReport{
		SessionID:        r.sessionID,
		OrganizationID:   r.orgID,
		Driver:           r.driver,
		TranscriptChunks: chunks,
		Truncated:        truncated,
	})
	if err != nil {
		logger.Warn(fmt.Sprintf("session transcript flush: marshal: %v", err))
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, listenerCertReportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, r.reportURL, bytes.NewReader(body))
	if err != nil {
		logger.Warn(fmt.Sprintf("session transcript flush: build request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := (&http.Client{Timeout: listenerCertReportTimeout}).Do(req)
	if err != nil {
		logger.Warn(fmt.Sprintf("session transcript flush failed session=%q: %v", r.sessionID, err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		logger.Warn(fmt.Sprintf("session transcript flush rejected session=%q (%d): %s", r.sessionID, resp.StatusCode, string(raw)))
	}
}

// newLocalSessionID mints a random session id for listener-mode connections that never get one
// assigned by the gateway's control-plane SessionStarted call.
func newLocalSessionID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure is essentially unreachable on any real OS; fall back to a
		// time-derived id rather than leaving the transcript unlabeled.
		return fmt.Sprintf("local-%d", time.Now().UnixNano())
	}
	return "local-" + hex.EncodeToString(buf)
}
