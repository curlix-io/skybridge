package dbquery

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/curlix-io/skybridge/internal/mask"
	_ "github.com/go-sql-driver/mysql"
)

func executeMySQL(ctx context.Context, target Target, database, q string, opts Options, masker mask.Masker) (map[string]any, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, errEmptyQuery
	}
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return nil, fmt.Errorf("mysql target missing host")
	}
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&timeout=30s", urlEscape(user), urlEscape(pass), host, dbName)
	db, err := sql.Open("mysql", dsn)
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
	objID := objectID(opts.OrgID, "mysql", dbName, dbName)
	masked, err := maskRows(ctx, masker, opts.Detector, opts.ProposeStore, objID, cols, data)
	if err != nil {
		return nil, err
	}
	return tabularResult(cols, masked), nil
}
