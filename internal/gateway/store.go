package gateway

import (
	"context"
	"time"

	"github.com/curlix-io/skybridge/internal/tunnel"
)

// Store records the lifecycle of native-access sessions the gateway relays. An external control
// plane is the single writer of the durable session store; this seam lets the gateway *report* what
// it knows (target, timing, byte volume) over HTTP without itself touching a database. Actor/lease
// attribution is optional today and is filled in once credential handoff lands.
//
// All methods are best-effort from the relay's perspective: a recording failure must never break or
// delay a live database session.
type Store interface {
	// SessionStarted is called when a native client connection is relayed to an agent. It returns an
	// opaque session id (assigned by the control plane) used to close the session later; an empty id
	// is valid and simply means "no close call will be made".
	SessionStarted(ctx context.Context, rec SessionRecord) (sessionID string, err error)
	// SessionEnded is called when the relay finishes, with the byte volume and outcome.
	SessionEnded(ctx context.Context, sessionID string, res SessionResult) error
	// SessionTranscript forwards a session-replay transcript chunk batch, relayed unmodified from
	// the agent (which built it from already-masked traffic on its side of the tunnel — see
	// internal/agent/agent.go). Called on the agent's flush, over the same gateway<->agent tunnel
	// control channel the session-lifecycle stream uses; the gateway itself never inspects the
	// chunk content, only relays it to the control plane. Best-effort, same as SessionEnded.
	SessionTranscript(ctx context.Context, sessionID string, chunks TranscriptChunks) error
}

// TranscriptChunks is one flush batch of session-replay chunks (already redacted/masked by the
// time they reach here — see studio_session_transcripts.py on the control-plane side for the
// storage/redaction contract). Truncated is set once the agent's own byte cap is hit; subsequent
// batches for the same session stop being sent. OrgID is required by the control plane's RLS (the
// session row it belongs to is org-scoped) — the gateway fills it in from the agent connection
// that sent the transcript (see Gateway.handleTranscript), since the agent process itself serves
// one org and doesn't otherwise stamp it on every control message.
type TranscriptChunks struct {
	OrgID     string                   `json:"organization_id"`
	Chunks    []tunnel.TranscriptChunk `json:"chunks"`
	Truncated bool                     `json:"truncated"`
}

// SessionRecord is what the gateway knows at the start of a native session.
//
// ResourceRoleID / ActorEmail are the attribution fields: when the registered target declares the
// resource role it fronts, the gateway forwards it so the control plane can attribute the session to
// that role (and, via the role's native-client credential lease, to its owner) instead of recording
// it unattributed. Both are optional and omitted from the wire when empty.
type SessionRecord struct {
	AgentID        string    `json:"agent_id"`
	OrgID          string    `json:"organization_id"`
	Target         string    `json:"target"`
	DBType         string    `json:"db_type"`
	ClientAddr     string    `json:"client_addr"`
	ResourceRoleID string    `json:"resource_role_id,omitempty"`
	ActorEmail     string    `json:"actor_email,omitempty"`
	StartedAt      time.Time `json:"started_at"`
}

// SessionResult is the outcome reported when a native session ends.
//
// DBUsername is the login the client authenticated as, sniffed from the relayed handshake. It is
// reported at close (the handshake is only observed once bytes flow) so the control plane can
// attribute the session to its owner via the matching credential lease — reliable even when several
// users share one resource role, since ephemeral logins are unique per grant. Empty when unknown.
type SessionResult struct {
	OrgID      string    `json:"organization_id"`
	EndedAt    time.Time `json:"ended_at"`
	BytesUp    int64     `json:"bytes_up"`   // client -> upstream (queries)
	BytesDown  int64     `json:"bytes_down"` // upstream -> client (masked results)
	Status     string    `json:"status"`     // "executed" | "cancelled"
	DBUsername string    `json:"db_username,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// NoopStore is the default: it records nothing.
type NoopStore struct{}

// SessionStarted implements Store.
func (NoopStore) SessionStarted(context.Context, SessionRecord) (string, error) { return "", nil }

// SessionEnded implements Store.
func (NoopStore) SessionEnded(context.Context, string, SessionResult) error { return nil }

// SessionTranscript implements Store.
func (NoopStore) SessionTranscript(context.Context, string, TranscriptChunks) error { return nil }
