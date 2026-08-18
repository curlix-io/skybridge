package dbquery

import (
	"context"
	"fmt"
	"strings"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"
)

// neo4jURI resolves the bolt/neo4j URI to dial for target. target.DSN, when set, is used verbatim
// (same convention as Mongo's Target.DSN — see target.go) so a caller-pushed dynamic connection
// override (dbexec.resolveTarget's "connection" arg) or a static SKYBRIDGE_ASSET_INVENTORY_NEO4J_URI
// fallback can carry a full "bolt://host:port" (or "neo4j+s://...", etc.) URI unchanged. Otherwise
// it composes "bolt://host:port" from target.Host, which Resolve/TargetFromOverride both populate
// as an already-combined host:port pair — the same convention executePostgres/executeMySQL rely on.
func neo4jURI(target Target) (string, error) {
	if dsn := strings.TrimSpace(target.DSN); dsn != "" {
		return dsn, nil
	}
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return "", fmt.Errorf("neo4j target missing host")
	}
	if strings.Contains(host, "://") {
		return host, nil
	}
	return "bolt://" + host, nil
}

// executeNeo4j runs a read-only Cypher statement against target's co-located Asset Inventory graph
// and shapes the result the same way executePostgres/executeMySQL/executeSnowflake do: a capped,
// masked []map[string]any keyed by the statement's returned column names, wrapped by
// tabularResult so db_query_neo4j's edge.Result looks identical in shape to the SQL/Mongo tools
// (see dbexec.extractRows, which reads raw["results"]["data"] the same way for every db_type).
func executeNeo4j(ctx context.Context, target Target, database, q string, opts Options, masker mask.Masker) (map[string]any, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, errEmptyQuery
	}
	uri, err := neo4jURI(target)
	if err != nil {
		return nil, err
	}
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	if dbName == "" {
		dbName = "neo4j"
	}

	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		return nil, err
	}
	defer driver.Close(ctx)

	session := driver.NewSession(ctx, neo4j.SessionConfig{
		AccessMode:   neo4j.AccessModeRead,
		DatabaseName: dbName,
	})
	defer session.Close(ctx)

	result, err := session.Run(ctx, q, nil)
	if err != nil {
		return nil, err
	}
	cols, err := result.Keys()
	if err != nil {
		return nil, err
	}

	data := make([]map[string]any, 0)
	for result.Next(ctx) {
		rec := result.Record()
		row := make(map[string]any, len(cols))
		for _, col := range cols {
			v, _ := rec.Get(col)
			row[col] = normalizeVal(neo4jScalar(v))
		}
		data = append(data, row)
		if opts.MaxRows > 0 && len(data) >= opts.MaxRows {
			break
		}
	}
	if err := result.Err(); err != nil {
		return nil, err
	}

	data = capRows(data, opts.MaxRows)
	objID := objectID(opts.OrgID, "neo4j", dbName, dbName)
	masked, err := maskRows(ctx, masker, opts.Detector, opts.ProposeStore, opts.SampleCollector, objID, cols, data)
	if err != nil {
		return nil, err
	}
	return tabularResult(cols, masked), nil
}

// neo4jScalar flattens the graph-typed values Cypher can return (dbtype.Node/Relationship/Path,
// plus nested lists/maps that may themselves contain graph types) into plain
// map[string]any/[]any/primitive shapes so maskRows' isFreeTextValue/fmt.Sprint pipeline (shared
// with the SQL/Mongo drivers) can mask string properties inside a returned node/relationship the
// same way it masks a plain SQL column — a raw dbtype.Node passed straight to fmt.Sprint would
// otherwise stringify as a Go struct dump instead of individually maskable property values.
func neo4jScalar(v any) any {
	switch x := v.(type) {
	case dbtype.Node:
		return map[string]any{"element_id": x.ElementId, "labels": x.Labels, "props": neo4jScalar(x.Props)}
	case dbtype.Relationship:
		return map[string]any{"element_id": x.ElementId, "type": x.Type, "start_element_id": x.StartElementId, "end_element_id": x.EndElementId, "props": neo4jScalar(x.Props)}
	case dbtype.Path:
		nodes := make([]any, len(x.Nodes))
		for i, n := range x.Nodes {
			nodes[i] = neo4jScalar(n)
		}
		rels := make([]any, len(x.Relationships))
		for i, r := range x.Relationships {
			rels[i] = neo4jScalar(r)
		}
		return map[string]any{"nodes": nodes, "relationships": rels}
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = neo4jScalar(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = neo4jScalar(vv)
		}
		return out
	default:
		return x
	}
}
