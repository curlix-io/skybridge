package dbquery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
)

// Options configures local query execution.
type Options struct {
	FallbackUser     string
	FallbackPassword string
	Masker           mask.Masker
	ApplyPII         bool
	MaxRows          int
	Timeout          time.Duration
	EnforceReadOnly  bool
}

func (o Options) withDefaults() Options {
	if o.MaxRows <= 0 {
		o.MaxRows = 1000
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	return o
}

// Result is the tabular execute payload shared by Studio dispatch and db_query_* tools.
type Result struct {
	Status  string           `json:"status"`
	Results map[string]any   `json:"results,omitempty"`
	Data    []map[string]any `json:"data,omitempty"`
	Columns []string         `json:"columns,omitempty"`
}

// Execute runs a statement against a resolved target.
func Execute(ctx context.Context, target Target, dbType, database, statement string, opts Options) (map[string]any, error) {
	opts = opts.withDefaults()
	if opts.EnforceReadOnly {
		if normalizeDBType(dbType) == "mongo" {
			if err := enforceReadOnlyMongo(statement); err != nil {
				return nil, err
			}
		} else if err := enforceReadOnlySQL(statement); err != nil {
			return nil, err
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	masker := opts.Masker
	if !opts.ApplyPII {
		masker = nil
	}

	switch normalizeDBType(dbType) {
	case "postgres":
		return executePostgres(runCtx, target, database, statement, opts, masker)
	case "mysql":
		return executeMySQL(runCtx, target, database, statement, opts, masker)
	case "mongo":
		return executeMongo(runCtx, target, database, statement, opts, masker)
	default:
		return nil, fmt.Errorf("unsupported db_type %q", dbType)
	}
}

func creds(target Target, fallbackUser, fallbackPass string) (user, pass string) {
	user = strings.TrimSpace(target.User)
	if user == "" {
		user = strings.TrimSpace(fallbackUser)
	}
	pass = target.Password
	if pass == "" {
		pass = fallbackPass
	}
	return user, pass
}

func urlEscape(s string) string {
	r := strings.NewReplacer("@", "%40", ":", "%3A", "/", "%2F")
	return r.Replace(s)
}

func normalizeVal(v any) any {
	switch x := v.(type) {
	case []byte:
		return string(x)
	default:
		return v
	}
}

func tabularResult(cols []string, rows []map[string]any) map[string]any {
	return map[string]any{
		"status": "success",
		"results": map[string]any{
			"data":    rows,
			"columns": cols,
		},
	}
}

func capRows(rows []map[string]any, max int) []map[string]any {
	if max <= 0 || len(rows) <= max {
		return rows
	}
	return rows[:max]
}

var errEmptyQuery = errors.New("empty query")
