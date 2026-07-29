package tunnel

import "encoding/json"

// Control messages ride the control channel (connID 0). They are versioned JSON so the contract can
// add fields without breaking older peers.

// ControlKind enumerates the control message kinds.
const (
	KindRegister    = "register"     // agent -> gateway: announce identity (org-scoped; no target list)
	KindRegisterAck = "register_ack" // gateway -> agent: accept/reject the registration
	KindHeartbeat   = "heartbeat"    // both directions: liveness
)

// Control is a control-channel message. There is no target list here: the gateway resolves a
// target's addr/db_type live, per client connection, and pushes it on the stream-open payload (see
// OpenMeta) instead of caching what the agent announces at registration.
type Control struct {
	Kind    string `json:"kind"`
	AgentID string `json:"agent_id,omitempty"`
	OrgID   string `json:"org_id,omitempty"` // tenant the agent belongs to; the gateway routes client
	// connections to an agent by this org id (one agent process serves one org).
	Token string `json:"token,omitempty"`
	OK    bool   `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
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
