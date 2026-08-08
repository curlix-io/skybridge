package agent

import (
	"log"
	"sync"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire"
)

// transcriptRecorder implements wire.Recorder by buffering chunks in memory (up to a byte cap)
// and flushing them as one tunnel.KindTranscript control message when the session ends — see
// serveStream in agent.go. Safe for concurrent use: the wire engines call RecordInput/RecordOutput
// from separate goroutines (client->server and server->client run concurrently).
type transcriptRecorder struct {
	sessionID string
	maxBytes  int

	mu        sync.Mutex
	chunks    []tunnel.TranscriptChunk
	totalSize int
	truncated bool
}

// newTranscriptRecorder returns a live recorder when replay is enabled and the gateway assigned a
// session id, or wire.NoopRecorder{} otherwise (disabled, or a deployment running without control-
// plane session recording).
func newTranscriptRecorder(sessionID string, cfg config.Agent) wire.Recorder {
	if !cfg.SessionReplayEnabled || sessionID == "" {
		return wire.NoopRecorder{}
	}
	maxBytes := cfg.SessionReplayMaxBytes
	if maxBytes <= 0 {
		maxBytes = 5 << 20
	}
	return &transcriptRecorder{sessionID: sessionID, maxBytes: maxBytes}
}

func (r *transcriptRecorder) append(direction, text string) {
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
func (r *transcriptRecorder) RecordInput(raw []byte) {
	if len(raw) == 0 {
		return
	}
	r.append("input", string(raw))
}

// RecordOutput implements wire.Recorder.
func (r *transcriptRecorder) RecordOutput(text string) {
	if text == "" {
		return
	}
	r.append("output", text)
}

// flushTranscript sends a recorder's accumulated chunks to the gateway as one control message,
// best-effort — a flush failure must never affect the already-completed database session. No-op
// for wire.NoopRecorder{} (replay disabled) or when there is nothing to send.
func flushTranscript(recorder wire.Recorder, sess *tunnel.Session, logger *log.Logger) {
	r, ok := recorder.(*transcriptRecorder)
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
	err := sess.SendControl(tunnel.Control{
		Kind:             tunnel.KindTranscript,
		SessionID:        r.sessionID,
		TranscriptChunks: chunks,
		Truncated:        truncated,
	})
	if err != nil && logger != nil {
		logger.Printf("session transcript flush failed session=%q: %v", r.sessionID, err)
	}
}
