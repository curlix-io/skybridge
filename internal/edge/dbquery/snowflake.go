package dbquery

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/curlix-io/skybridge/internal/mask"
	sf "github.com/snowflakedb/gosnowflake"
)

// executeSnowflake dials Snowflake's SQL API the same way executePostgres/executeMySQL dial their
// engines — via the standard database/sql interface — so the resulting rows flow through the same
// maskRows call before ever leaving the edge process. Target.Host carries the account locator
// (e.g. "xy12345.us-east-1"), not a host:port pair; gosnowflake resolves the real endpoint itself.
func executeSnowflake(ctx context.Context, target Target, database, q string, opts Options, masker mask.Masker) (map[string]any, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, errEmptyQuery
	}
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	account := strings.TrimSpace(target.Host)
	if account == "" {
		return nil, fmt.Errorf("snowflake target missing account locator")
	}
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	cfg := &sf.Config{
		Account:   account,
		User:      user,
		Password:  pass,
		Database:  dbName,
		Schema:    strings.TrimSpace(target.Schema),
		Warehouse: strings.TrimSpace(target.Warehouse),
		Role:      strings.TrimSpace(target.Role),
	}
	dsn, err := sf.DSN(cfg)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("snowflake", dsn)
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
	objID := objectID(opts.OrgID, "snowflake", dbName, dbName)
	masked, err := maskRows(ctx, masker, opts.Detector, opts.ProposeStore, opts.SampleCollector, objID, cols, data)
	if err != nil {
		return nil, err
	}
	return tabularResult(cols, masked), nil
}
