// Package sqlsampler implements aiclassifier.Sampler over database/sql for Postgres and MySQL —
// the read-only, off-the-hot-path row sampling docs/AI_PATH_LABELLING_DESIGN.md §5.2 describes.
// This is a sampling connection, not a wire-proxy or client-session connection: it exists purely to
// feed the periodic classification scan (cmd/skybridge-labeller) and never touches live query
// traffic. Callers are expected to use a dedicated, read-only credential — the same posture
// SKYBRIDGE_POSTGRES_CATALOG_DSN already uses for the wire proxy's catalog lookups (see
// REDACTION.md's "Postgres table-identity resolution").
package sqlsampler

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Sampler implements aiclassifier.Sampler by running a bounded SELECT per (objectID, fieldPath).
// Zero value is not usable; call New.
type Sampler struct {
	db *sql.DB
	// quoteIdent quotes a table/column identifier per the target dialect (double quotes for
	// Postgres, backticks for MySQL) — table/column names come only from ListColumns' own
	// information_schema query or from Config.Tables (operator-supplied config, not
	// client-controlled input), never from an untrusted source, but quoting them still avoids
	// silently breaking on names that need it (mixed case, reserved words).
	quoteIdent func(string) string
}

// New returns a Sampler over db. driver selects identifier-quoting style ("postgres" or "mysql");
// an unrecognized driver defaults to Postgres-style double-quoting.
func New(db *sql.DB, driver string) *Sampler {
	quote := quotePostgresIdent
	if driver == "mysql" {
		quote = quoteMySQLIdent
	}
	return &Sampler{db: db, quoteIdent: quote}
}

func quotePostgresIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
func quoteMySQLIdent(s string) string    { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// tableFromObjectID extracts the bare table name from an ObjectID shaped
// "{org}:{driver}:{database}:{table}" (internal/edge/dbquery's objectID convention, also used by
// internal/pathlabel/remotestore) — the last colon-separated segment.
func tableFromObjectID(objectID string) (table string, ok bool) {
	parts := strings.Split(objectID, ":")
	if len(parts) < 4 {
		return "", false
	}
	return parts[len(parts)-1], true
}

// Sample implements aiclassifier.Sampler: SELECT fieldPath FROM table WHERE fieldPath IS NOT NULL
// LIMIT maxSamples, over the table named by objectID's last segment. ok=false on any error (bad
// ObjectID shape, query failure, table/column that doesn't exist) or an empty result — a sampling
// failure for one field must never abort the caller's scan over the rest of an object's fields
// (aiclassifier.Sampler's own doc comment).
func (s *Sampler) Sample(ctx context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool) {
	table, ok := tableFromObjectID(objectID)
	if !ok || fieldPath == "" || maxSamples <= 0 {
		return nil, false
	}
	col := s.quoteIdent(fieldPath)
	query := fmt.Sprintf("SELECT %s FROM %s WHERE %s IS NOT NULL LIMIT %d", col, s.quoteIdent(table), col, maxSamples)
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, false
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var v sql.NullString
		if err := rows.Scan(&v); err != nil {
			return nil, false
		}
		if v.Valid {
			out = append(out, v.String)
		}
	}
	if err := rows.Err(); err != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

// ListColumns returns table's column names via information_schema, the same catalog view both
// Postgres and MySQL support. schema is a Postgres schema name (typically "public") or, for MySQL
// (which has no separate schema concept from database), the database name itself — the caller
// supplies whichever is correct for its driver, this method makes no assumption about which one
// Config.Database means. Used by the scan job to discover which fields to classify per table — this
// package intentionally does not cache the result, since a schema-scan job runs infrequently enough
// (docs/AI_PATH_LABELLING_DESIGN.md §5.2's periodic-not-hot-path posture) that a fresh lookup every
// run is simpler than invalidating a cache on schema changes.
func (s *Sampler) ListColumns(ctx context.Context, schema, table string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2",
		schema, table)
	if err != nil {
		// MySQL's driver doesn't support $1/$2 placeholders — retry with ? placeholders rather than
		// branching on driver name a second time in this method.
		rows, err = s.db.QueryContext(ctx,
			"SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?",
			schema, table)
		if err != nil {
			return nil, err
		}
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return nil, err
		}
		out = append(out, col)
	}
	return out, rows.Err()
}

var _ interface {
	Sample(ctx context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool)
} = (*Sampler)(nil)
