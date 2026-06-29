package gateway

import (
	"context"
	"time"
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
