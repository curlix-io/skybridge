//go:build querystudio

package dbquery

import (
	"encoding/json"
	"strings"

	"github.com/curlix-io/skybridge/internal/tunnel"
)

// Target declares a database the edge can reach for one-shot exec or Studio dispatch.
type Target struct {
	DBType       string `json:"db_type"`
	AWSAccountID string `json:"aws_account_id"`
	DatabaseName string `json:"database_name"`
	Host         string `json:"host"`
	User         string `json:"user,omitempty"`
	Password     string `json:"password,omitempty"`
	SSLMode      string `json:"sslmode,omitempty"` // postgres
	Name         string `json:"name,omitempty"`    // optional logical name (wire targets)
}

// ParseTargets decodes SKYBRIDGE_STUDIO_TARGETS / SKYBRIDGE_TARGETS JSON arrays.
func ParseTargets(raw string) []Target {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var ts []Target
	if err := json.Unmarshal([]byte(raw), &ts); err != nil {
		return nil
	}
	for i := range ts {
		ts[i].DBType = normalizeDBType(ts[i].DBType)
	}
	return ts
}

// MergeWireTargets appends tunnel.Target entries (SKYBRIDGE_TARGETS wire-proxy shape) as exec targets.
func MergeWireTargets(studio []Target, wire []tunnel.Target) []Target {
	out := append([]Target(nil), studio...)
	for _, w := range wire {
		out = append(out, Target{
			Name:         w.Name,
			DBType:       normalizeDBType(w.DBType),
			Host:         w.Addr,
			DatabaseName: w.Name,
		})
	}
	return out
}

func normalizeDBType(dbType string) string {
	d := strings.ToLower(strings.TrimSpace(dbType))
	switch d {
	case "postgresql":
		return "postgres"
	case "mongodb":
		return "mongo"
	default:
		return d
	}
}

func (t Target) matches(dbType, account, database string) bool {
	if t.DBType != "" && t.DBType != normalizeDBType(dbType) {
		return false
	}
	if t.AWSAccountID != "" && t.AWSAccountID != account {
		return false
	}
	if t.DatabaseName != "" && t.DatabaseName != database {
		return false
	}
	if t.Name != "" && t.DatabaseName == "" && t.Name != database {
		return false
	}
	return true
}

// Resolve picks the first target matching db_type + scope + database.
func Resolve(targets []Target, dbType, account, database string) (Target, bool) {
	for _, t := range targets {
		if t.matches(dbType, account, database) {
			return t, true
		}
	}
	return Target{}, false
}
