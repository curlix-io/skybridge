package dbquery

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoFindRe = regexp.MustCompile(`(?is)^\s*db\.([a-zA-Z0-9_]+)\.find\s*\((.*)\)\s*(?:\.\s*limit\s*\(\s*(\d+)\s*\)\s*)?;?\s*$`)
var mongoAggRe = regexp.MustCompile(`(?is)^\s*db\.([a-zA-Z0-9_]+)\.aggregate\s*\((.*)\)\s*(?:\.\s*limit\s*\(\s*(\d+)\s*\)\s*)?;?\s*$`)

type mongoParsed struct {
	collection string
	op         string // find | aggregate | ping
	filter     bson.M
	pipeline   bson.A
	limit      int64
}

// mongoPingStatement is the sole recognized connectivity-check statement for db_query_mongo: no
// find/aggregate op assumes a real collection exists, so a caller with no known collection (e.g.
// Test Connection, see connections.py's _test_connection_via_connector_enabled) has nothing to
// probe with. "ping" runs the admin ping command against the target database instead — it
// succeeds as long as the server is reachable and authenticated, regardless of what collections
// exist. Matched case-insensitively, trimmed, with no other statement shape accepted for it.
func parseMongoStatement(stmt string) (mongoParsed, error) {
	stmt = strings.TrimSpace(stmt)
	if stmt == "" {
		return mongoParsed{}, errEmptyQuery
	}
	if strings.EqualFold(stmt, "ping") {
		return mongoParsed{op: "ping"}, nil
	}
	if m := mongoFindRe.FindStringSubmatch(stmt); len(m) >= 3 {
		filter := bson.M{}
		arg := strings.TrimSpace(m[2])
		if arg != "" {
			if err := bson.UnmarshalExtJSON([]byte(arg), false, &filter); err != nil {
				return mongoParsed{}, fmt.Errorf("invalid find filter: %w", err)
			}
		}
		limit := int64(0)
		if len(m) >= 4 && strings.TrimSpace(m[3]) != "" {
			fmt.Sscanf(m[3], "%d", &limit)
		}
		return mongoParsed{collection: m[1], op: "find", filter: filter, limit: limit}, nil
	}
	if m := mongoAggRe.FindStringSubmatch(stmt); len(m) >= 3 {
		pipeline := bson.A{}
		arg := strings.TrimSpace(m[2])
		if arg == "" {
			return mongoParsed{}, fmt.Errorf("aggregate requires a pipeline")
		}
		if err := bson.UnmarshalExtJSON([]byte(arg), false, &pipeline); err != nil {
			return mongoParsed{}, fmt.Errorf("invalid aggregate pipeline: %w", err)
		}
		limit := int64(0)
		if len(m) >= 4 && strings.TrimSpace(m[3]) != "" {
			fmt.Sscanf(m[3], "%d", &limit)
		}
		return mongoParsed{collection: m[1], op: "aggregate", pipeline: pipeline, limit: limit}, nil
	}
	// JSON fallback: {"collection":"users","filter":{}} or {"collection":"users","pipeline":[...]}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stmt), &raw); err == nil {
		var collection string
		if b, ok := raw["collection"]; ok {
			_ = json.Unmarshal(b, &collection)
		}
		if collection == "" {
			return mongoParsed{}, fmt.Errorf("mongo JSON statement requires collection")
		}
		if b, ok := raw["pipeline"]; ok {
			var pipeline bson.A
			if err := json.Unmarshal(b, &pipeline); err != nil {
				return mongoParsed{}, err
			}
			return mongoParsed{collection: collection, op: "aggregate", pipeline: pipeline}, nil
		}
		filter := bson.M{}
		if b, ok := raw["filter"]; ok {
			if err := json.Unmarshal(b, &filter); err != nil {
				return mongoParsed{}, err
			}
		}
		return mongoParsed{collection: collection, op: "find", filter: filter}, nil
	}
	return mongoParsed{}, fmt.Errorf("unsupported mongo statement shape (use db.COL.find({}) or db.COL.aggregate([...]))")
}

// mongoURI resolves the URI executeMongo/executeWriteMongo connect with. target.DSN, when set
// (see its doc comment — populated by TargetFromOverride from a per-call "connection" argument),
// is used verbatim ahead of composing one from Host/User/Password: a real dispatched URI may carry
// replica-set members, mongodb+srv://, or auth/topology query params that a host/port/user/pass
// decomposition can't reconstruct.
func mongoURI(target Target, database string, opts Options) (string, string, error) {
	if dsn := strings.TrimSpace(target.DSN); dsn != "" {
		dbName := strings.TrimSpace(database)
		if dbName == "" {
			dbName = strings.TrimSpace(target.DatabaseName)
		}
		return dsn, dbName, nil
	}
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return "", "", fmt.Errorf("mongo target missing host")
	}
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	uri := fmt.Sprintf("mongodb://%s:%s@%s/%s", urlEscape(user), urlEscape(pass), host, dbName)
	if user == "" && pass == "" {
		uri = fmt.Sprintf("mongodb://%s/%s", host, dbName)
	}
	return uri, dbName, nil
}

func executeMongo(ctx context.Context, target Target, database, stmt string, opts Options, masker mask.Masker) (map[string]any, error) {
	parsed, err := parseMongoStatement(stmt)
	if err != nil {
		return nil, err
	}
	uri, dbName, err := mongoURI(target, database, opts)
	if err != nil {
		return nil, err
	}
	clientOpts := options.Client().ApplyURI(uri).SetConnectTimeout(15 * time.Second)
	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	if parsed.op == "ping" {
		if err := client.Database(dbName).RunCommand(ctx, bson.D{{Key: "ping", Value: 1}}).Err(); err != nil {
			return nil, err
		}
		return map[string]any{
			"status": "success",
			"results": map[string]any{
				"data": []map[string]any{{"ok": float64(1)}},
			},
		}, nil
	}

	coll := client.Database(dbName).Collection(parsed.collection)
	limit := opts.MaxRows
	if parsed.limit > 0 && parsed.limit < int64(limit) {
		limit = int(parsed.limit)
	}
	findOpts := options.Find().SetLimit(int64(limit))

	var cursor *mongo.Cursor
	switch parsed.op {
	case "find":
		cursor, err = coll.Find(ctx, parsed.filter, findOpts)
	case "aggregate":
		cursor, err = coll.Aggregate(ctx, parsed.pipeline)
	default:
		return nil, fmt.Errorf("unsupported mongo op %q", parsed.op)
	}
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	docs := make([]map[string]any, 0)
	for cursor.Next(ctx) {
		var doc map[string]any
		if err := cursor.Decode(&doc); err != nil {
			return nil, err
		}
		docs = append(docs, normalizeBSONDoc(doc))
		if len(docs) >= limit {
			break
		}
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	objID := objectID(opts.OrgID, "mongo", dbName, parsed.collection)
	masked, err := maskDocuments(ctx, masker, opts.Detector, opts.ProposeStore, opts.SampleCollector, objID, docs)
	if err != nil {
		return nil, err
	}
	for i, doc := range masked {
		masked[i] = flattenBSON(doc)
	}
	return map[string]any{
		"status": "success",
		"results": map[string]any{
			"data": masked,
		},
	}, nil
}

// normalizeBSONDoc converts the driver's decoded types (bson.M/primitive.M, bson.A/primitive.A —
// named types over map[string]any/[]any) into plain map[string]any/[]any recursively, so
// docpath.Walk's type switch (which matches only the plain, unnamed types) sees every nested level.
// String/number/bool/nil leaves pass through unchanged; anything else (e.g. primitive.ObjectID,
// primitive.DateTime) is left as-is since docpath.Walk only visits string leaves anyway.
func normalizeBSONDoc(doc map[string]any) map[string]any {
	return normalizeBSONValue(doc).(map[string]any)
}

func normalizeBSONValue(v any) any {
	switch x := v.(type) {
	case bson.M:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeBSONValue(vv)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = normalizeBSONValue(vv)
		}
		return out
	case bson.A:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = normalizeBSONValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = normalizeBSONValue(vv)
		}
		return out
	default:
		return v
	}
}

func flattenBSON(doc map[string]any) map[string]any {
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		out[k] = stringifyBSON(v)
	}
	return out
}

func stringifyBSON(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case string, bool, float64, int32, int64, json.Number:
		return x
	case bson.M, map[string]any:
		b, _ := bson.MarshalExtJSON(x, false, false)
		return string(b)
	case bson.A, []any:
		b, _ := bson.MarshalExtJSON(x, false, false)
		return string(b)
	default:
		return fmt.Sprint(v)
	}
}
