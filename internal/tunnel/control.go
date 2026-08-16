package tunnel

import "encoding/json"

// Control messages ride the control channel (connID 0). They are versioned JSON so the contract can
// add fields without breaking older peers.

// ControlKind enumerates the control message kinds.
const (
	KindRegister    = "register"     // agent -> gateway: announce identity (org-scoped; no target list)
	KindRegisterAck = "register_ack" // gateway -> agent: accept/reject the registration
	KindHeartbeat   = "heartbeat"    // both directions: liveness
	// KindTranscript is agent -> gateway: a session-replay transcript flush (see the session replay
	// design doc). Chunks are already masked (the wire engine's Recorder only ever sees
	// already-masked output) — the gateway relays them to the control plane unmodified via
	// Store.SessionTranscript, never inspecting content itself.
	KindTranscript = "transcript"
)

// Control is a control-channel message. There is no target list here: the gateway resolves a
// target's addr/db_type live, per client connection, and pushes it on the stream-open payload (see
// OpenMeta) instead of caching what the agent announces at registration.
type Control struct {
	Kind    string `json:"kind"`
	AgentID string `json:"agent_id,omitempty"`
	OrgID   string `json:"org_id,omitempty"` // tenant the agent belongs to; the gateway routes client
	// connections to an agent by this org id (one agent process serves one org). Registration itself
	// is authenticated by the connection's verified mTLS client certificate, not a field in here —
	// there is no bearer-token registration mode.
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`

	// KindTranscript fields.
	SessionID        string            `json:"session_id,omitempty"`
	TranscriptChunks []TranscriptChunk `json:"chunks,omitempty"`
	Truncated        bool              `json:"truncated,omitempty"`
}

// TranscriptChunk is one input or output unit of a session-replay transcript, as produced by a
// wire engine's Recorder (see internal/wire.Recorder) and relayed verbatim by the gateway to the
// control plane.
type TranscriptChunk struct {
	Seq       int    `json:"seq"`
	Direction string `json:"direction"` // "input" | "output"
	Text      string `json:"text"`
	Bytes     int    `json:"bytes"`
}

// Target describes a database, either from static listener-mode config (SKYBRIDGE_TARGETS) or as
// the shape a gateway TargetResolver returns for one tunnel-mode connection.
type Target struct {
	Name   string `json:"name"`    // logical name clients select (e.g. "prod-users")
	Addr   string `json:"addr"`    // upstream host:port the agent dials
	DBType string `json:"db_type"` // postgres | mysql | mongodb

	// Attribution (optional). A target usually fronts a single Studio resource role; declaring it
	// here lets the gateway attribute relayed sessions to that role (and, via the role's native-client
	// credential lease, to the owning actor) instead of recording them unattributed. ActorEmail is
	// only meaningful for a target dedicated to one user; leave it empty otherwise.
	ResourceRoleID string `json:"resource_role_id,omitempty"`
	ActorEmail     string `json:"actor_email,omitempty"`
}

func (c Control) encode() []byte {
	b, _ := json.Marshal(c)
	return b
}

func decodeControl(b []byte) (Control, error) {
	var c Control
	err := json.Unmarshal(b, &c)
	return c, err
}

// OpenMeta is the payload of an OPEN frame: which target the new stream is proxied to, plus (when
// the gateway resolved it live via a TargetResolver) the addr/db_type/attribution the agent needs —
// the agent dials Addr directly and no longer consults a local target cache.
type OpenMeta struct {
	Target         string `json:"target"`
	Addr           string `json:"addr,omitempty"`
	DBType         string `json:"db_type,omitempty"`
	ResourceRoleID string `json:"resource_role_id,omitempty"`
	ActorEmail     string `json:"actor_email,omitempty"`

	// SessionID is the control-plane session id the gateway already opened (via SessionStarted)
	// before calling Open — session replay needs it so the agent, which builds
	// the transcript from already-masked traffic, can tag chunks with the session they belong to
	// when it flushes them back over the tunnel control channel (see internal/agent/agent.go's
	// serveStream). Empty when session recording (or replay specifically) is not enabled — the
	// agent then runs a NoopRecorder.
	SessionID string `json:"session_id,omitempty"`
}

// Encode serializes the open metadata for Session.Open.
func (m OpenMeta) Encode() []byte {
	b, _ := json.Marshal(m)
	return b
}

// DecodeOpenMeta parses an OPEN frame payload (use it on Stream.Meta()).
func DecodeOpenMeta(b []byte) (OpenMeta, error) {
	var m OpenMeta
	err := json.Unmarshal(b, &m)
	return m, err
}
