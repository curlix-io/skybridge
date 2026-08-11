package agent

import (
	"bytes"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire"
)

func TestNewTranscriptRecorderNoopWhenDisabled(t *testing.T) {
	r := newTranscriptRecorder("sess-1", config.Agent{})
	if _, ok := r.(wire.NoopRecorder); !ok {
		t.Fatalf("expected wire.NoopRecorder when replay is disabled, got %T", r)
	}
}

func TestNewTranscriptRecorderNoopWhenNoSessionID(t *testing.T) {
	r := newTranscriptRecorder("", config.Agent{SessionReplayEnabled: true})
	if _, ok := r.(wire.NoopRecorder); !ok {
		t.Fatalf("expected wire.NoopRecorder when session id is empty, got %T", r)
	}
}

func TestNewTranscriptRecorderLiveWhenEnabled(t *testing.T) {
	r := newTranscriptRecorder("sess-1", config.Agent{SessionReplayEnabled: true})
	tr, ok := r.(*transcriptRecorder)
	if !ok {
		t.Fatalf("expected *transcriptRecorder, got %T", r)
	}
	if tr.sessionID != "sess-1" || tr.maxBytes != 5<<20 {
		t.Fatalf("unexpected recorder: %+v", tr)
	}
}

func TestNewTranscriptRecorderRespectsMaxBytesOverride(t *testing.T) {
	r := newTranscriptRecorder("sess-1", config.Agent{SessionReplayEnabled: true, SessionReplayMaxBytes: 100})
	tr := r.(*transcriptRecorder)
	if tr.maxBytes != 100 {
		t.Fatalf("expected overridden maxBytes=100, got %d", tr.maxBytes)
	}
}

func TestTranscriptRecorderRecordInputAndOutput(t *testing.T) {
	r := newTranscriptRecorder("sess-1", config.Agent{SessionReplayEnabled: true}).(*transcriptRecorder)
	r.RecordInput([]byte("hello"))
	r.RecordOutput("world")
	r.RecordInput(nil) // no-op
	r.RecordOutput("") // no-op

	if len(r.chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d: %+v", len(r.chunks), r.chunks)
	}
	if r.chunks[0].Direction != "input" || r.chunks[0].Text != "hello" {
		t.Fatalf("unexpected first chunk: %+v", r.chunks[0])
	}
	if r.chunks[1].Direction != "output" || r.chunks[1].Text != "world" {
		t.Fatalf("unexpected second chunk: %+v", r.chunks[1])
	}
}

func TestTranscriptRecorderTruncatesPastMaxBytes(t *testing.T) {
	r := newTranscriptRecorder("sess-1", config.Agent{SessionReplayEnabled: true, SessionReplayMaxBytes: 5}).(*transcriptRecorder)
	r.RecordInput([]byte("hello")) // exactly at the cap, fits
	r.RecordInput([]byte("more"))  // pushes past the cap -> truncated
	r.RecordOutput("ignored-after-truncation")

	if !r.truncated {
		t.Fatal("expected recorder to be marked truncated")
	}
	if len(r.chunks) != 1 {
		t.Fatalf("expected only the first chunk to be recorded, got %d", len(r.chunks))
	}
}

func TestFlushTranscriptNoopForNonTranscriptRecorder(t *testing.T) {
	agentEnd, peerEnd := net.Pipe()
	defer agentEnd.Close()
	defer peerEnd.Close()
	sess := tunnel.Client(agentEnd)
	defer sess.Close()

	// Must not panic or block for wire.NoopRecorder{}.
	flushTranscript(wire.NoopRecorder{}, sess, slog.Default())
}

func TestFlushTranscriptNoopWhenNoChunksRecorded(t *testing.T) {
	agentEnd, peerEnd := net.Pipe()
	defer agentEnd.Close()
	defer peerEnd.Close()
	sess := tunnel.Client(agentEnd)
	defer sess.Close()

	r := newTranscriptRecorder("sess-1", config.Agent{SessionReplayEnabled: true})
	// No RecordInput/RecordOutput calls -> nothing to flush.
	flushTranscript(r, sess, slog.Default())
}

func TestFlushTranscriptSendsAccumulatedChunks(t *testing.T) {
	agentEnd, peerEnd := net.Pipe()
	defer agentEnd.Close()

	clientSess := tunnel.Client(agentEnd)
	defer clientSess.Close()
	serverSess := tunnel.Server(peerEnd)
	defer serverSess.Close()

	r := newTranscriptRecorder("sess-1", config.Agent{SessionReplayEnabled: true}).(*transcriptRecorder)
	r.RecordInput([]byte("in"))
	r.RecordOutput("out")

	done := make(chan tunnel.Control, 1)
	go func() {
		ctrl, err := serverSess.NextControl()
		if err != nil {
			return
		}
		done <- ctrl
	}()

	flushTranscript(r, clientSess, slog.Default())

	select {
	case ctrl := <-done:
		if ctrl.Kind != tunnel.KindTranscript || ctrl.SessionID != "sess-1" || len(ctrl.TranscriptChunks) != 2 {
			t.Fatalf("unexpected transcript control: %+v", ctrl)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for transcript control message")
	}
}

func TestFlushTranscriptLogsFailureWithoutPanicking(t *testing.T) {
	agentEnd, peerEnd := net.Pipe()
	defer agentEnd.Close()
	sess := tunnel.Client(agentEnd)
	_ = peerEnd.Close() // break the pipe so SendControl fails
	_ = sess.Close()

	r := newTranscriptRecorder("sess-1", config.Agent{SessionReplayEnabled: true}).(*transcriptRecorder)
	r.RecordInput([]byte("in"))

	var buf bytes.Buffer
	flushTranscript(r, sess, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("transcript flush failed")) {
		t.Fatalf("expected a flush-failure log line, got %q", buf.String())
	}
}
