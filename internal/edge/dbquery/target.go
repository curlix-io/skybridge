package dbquery

import (
	"encoding/json"
	"fmt"
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
	// DSN carries a full connection URI when the target can't be decomposed into Host/User/
	// Password -- currently only populated for Mongo (replica-set members, mongodb+srv://
	// DNS-seedlist scheme, and auth/topology query params don't survive that decomposition,
	// unlike Postgres/MySQL DSNs). When set, executeMongo uses it directly instead of building a
	// URI from Host/User/Password. See docs/design/skybridge-dynamic-connection-catalog.md
	// (Curlix backend repo) for the per-call override this is populated from.
	DSN string `json:"dsn,omitempty"`
	SSLMode      string `json:"sslmode,omitempty"` // postgres
	Name         string `json:"name,omitempty"`    // optional logical name (wire targets)
	// Snowflake-only: Host carries the account locator (e.g. "xy12345.us-east-1"), not a
	// host:port pair — gosnowflake resolves the real endpoint from the account identifier.
	Warehouse string `json:"warehouse,omitempty"` // snowflake
	Role      string `json:"role,omitempty"`      // snowflake
	Schema    string `json:"schema,omitempty"`    // snowflake
	// DSN, when set, is used verbatim as the mongo connection URI instead of composing one from
	// Host/User/Password (see mongoURI in mongo.go). Mongo URIs commonly carry replica-set
	// members, the mongodb+srv:// DNS-seedlist scheme, and auth/topology query params that don't
	// survive a host/port/user/pass decomposition — a per-call override (see TargetFromOverride)
	// needs to pass the caller's already-resolved URI through unchanged rather than rebuild one.
	// Unused by postgres/mysql/snowflake, whose decomposed host+port+credential is sufficient.
	DSN string `json:"dsn,omitempty"`
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
	case "snowflake":
		return "snowflake"
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

// TargetFromOverride builds a Target from a per-call "connection" argument the control plane
// pushes alongside a db_query_*/db_execute_write dispatch, instead of requiring the database to
// already exist in the connector's static Targets/SKYBRIDGE_STUDIO_TARGETS config. This is what
// makes the control plane's per-call dynamic connection resolution (it re-resolves credentials
// fresh on every dispatch, rather than relying on a target list baked in at connector deploy
// time) actually take effect here — until this function existed, dbexec's run()/runWrite() only
// ever consulted Resolve() against the static list, so a database added to the control plane
// after the connector's last deploy always edge-missed and fell back to native-wire-proxy
// regardless of what the caller pushed.
//
// Expected shape (JSON-decoded into map[string]any, so numbers arrive as float64):
//
//	{"host": "db.internal", "port": 5432, "credential": {"user": "u", "secret": "p"}, "dsn": "..."}
//
// "host"+"port" combine into Target.Host as "host:port" (see postgres.go/mysql.go/mongo.go, all
// of which treat Target.Host as an already-combined host:port pair). "dsn", when present, is only
// meaningful for mongo (see Target.DSN's doc comment) and is carried through verbatim.
// database is used to populate Target.DatabaseName so callers that read it (e.g. dbquery.Execute's
// default-database fallback) see the same value the caller resolved against. Returns ok=false when
// override is nil, not a map, or missing a usable host (for postgres/mysql/snowflake) — callers
// must fall back to Resolve() against the static list in that case, not treat it as a hard error.
func TargetFromOverride(dbType, database string, override map[string]any) (Target, bool) {
	if override == nil {
		return Target{}, false
	}
	dsn, _ := override["dsn"].(string)
	dsn = strings.TrimSpace(dsn)
	host, _ := override["host"].(string)
	host = strings.TrimSpace(host)
	if host == "" && dsn == "" {
		return Target{}, false
	}
	t := Target{
		DBType:       normalizeDBType(dbType),
		DatabaseName: strings.TrimSpace(database),
		DSN:          dsn,
	}
	if host != "" {
		t.Host = host
		if port := overridePort(override["port"]); port != "" {
			t.Host = host + ":" + port
		}
	}
	if cred, ok := override["credential"].(map[string]any); ok {
		if user, ok := cred["user"].(string); ok {
			t.User = user
		}
		if secret, ok := cred["secret"].(string); ok {
			t.Password = secret
		}
	}
	if t.Host == "" && t.DSN == "" {
		return Target{}, false
	}
	return t, true
}

// overridePort coerces the JSON-decoded "port" value (float64 from json.Unmarshal, or already a
// string/int if the caller built the map in Go rather than decoding JSON) into a string, or ""
// when absent/unparseable — absent is a normal case (e.g. mongo's dsn-only override).
func overridePort(v any) string {
	switch p := v.(type) {
	case float64:
		if p <= 0 {
			return ""
		}
		return strings.TrimSuffix(fmt.Sprintf("%.0f", p), ".0")
	case int:
		if p <= 0 {
			return ""
		}
		return fmt.Sprintf("%d", p)
	case string:
		return strings.TrimSpace(p)
	default:
		return ""
	}
}
