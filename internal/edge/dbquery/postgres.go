package dbquery

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/curlix-io/skybridge/internal/mask"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func executePostgres(ctx context.Context, target Target, database, q string, opts Options, masker mask.Masker) (map[string]any, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, errEmptyQuery
	}
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return nil, fmt.Errorf("postgres target missing host")
	}
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	sslmode := strings.TrimSpace(target.SSLMode)
	if sslmode == "" {
		sslmode = "require"
	}
	dsn := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s", urlEscape(user), urlEscape(pass), host, dbName, sslmode)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	data := make([]map[string]any, 0)
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			row[col] = normalizeVal(vals[i])
		}
		data = append(data, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	data = capRows(data, opts.MaxRows)
	objID := objectID(opts.OrgID, "postgres", dbName, dbName)
	masked, err := maskRows(ctx, masker, objID, cols, data)
	if err != nil {
		return nil, err
	}
	return tabularResult(cols, masked), nil
}
