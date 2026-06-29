package tunnel

import "encoding/json"

// Control messages ride the control channel (connID 0). They are versioned JSON so the contract can
// add fields without breaking older peers.

// ControlKind enumerates the control message kinds.
const (
	KindRegister    = "register"     // agent -> gateway: announce identity + served targets
	KindRegisterAck = "register_ack" // gateway -> agent: accept/reject the registration
	KindHeartbeat   = "heartbeat"    // both directions: liveness
)

// Control is a control-channel message.
type Control struct {
	Kind    string   `json:"kind"`
	AgentID string   `json:"agent_id,omitempty"`
	OrgID   string   `json:"org_id,omitempty"` // tenant the agent belongs to (for session attribution)
	Token   string   `json:"token,omitempty"`
	Targets []Target `json:"targets,omitempty"`
	OK      bool     `json:"ok,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Target describes a database the agent can reach inside the egress network.
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

// OpenMeta is the payload of an OPEN frame: which target the new stream should be proxied to.
type OpenMeta struct {
	Target string `json:"target"`
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
