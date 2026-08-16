package dbquery

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// executeWriteSQL runs statement through ExecContext rather than QueryContext — this is the write
// path used only by db_execute_write (internal/edge/dbexec), never by the read-only db_query_*
// tools. The statement is executed exactly as dispatched: no keyword classification, no rewriting.
// Whether a given statement should have been allowed at all is Curlix's own allow/deny decision
// made before dispatch, not something this package re-derives from the SQL text.
func executeWriteSQL(ctx context.Context, target Target, driver, database, statement string, opts Options) (map[string]any, error) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return nil, errEmptyQuery
	}
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	host := strings.TrimSpace(target.Host)
	if host == "" {
		return nil, fmt.Errorf("%s target missing host", driver)
	}
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}

	var dsn string
	switch driver {
	case "postgres":
		sslmode := strings.TrimSpace(target.SSLMode)
		if sslmode == "" {
			sslmode = "require"
		}
		dsn = fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s", urlEscape(user), urlEscape(pass), host, dbName, sslmode)
	case "mysql":
		dsn = fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&timeout=30s", urlEscape(user), urlEscape(pass), host, dbName)
	default:
		return nil, fmt.Errorf("unsupported write driver %q", driver)
	}
	sqlDriver := driver
	if driver == "postgres" {
		sqlDriver = "pgx"
	}
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	res, err := db.ExecContext(ctx, statement)
	if err != nil {
		return nil, err
	}
	affected, _ := res.RowsAffected()
	return map[string]any{
		"status": "success",
		"results": map[string]any{
			"rows_affected": affected,
		},
	}, nil
}

// executeWriteMongo runs a write operation (insertOne/updateOne/deleteOne/etc., or an aggregation
// pipeline containing $out/$merge) parsed from the dispatched shell-style statement. As with
// executeWriteSQL, the statement is trusted as-is — Curlix's own allow/deny decision, made before
// dispatch to db_execute_write, is what gates whether this call should have happened at all.
func executeWriteMongo(ctx context.Context, target Target, database, stmt string, opts Options) (map[string]any, error) {
	parsed, err := parseMongoWriteStatement(stmt)
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

	coll := client.Database(dbName).Collection(parsed.collection)
	result, err := runMongoWrite(ctx, coll, parsed)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"status": "success",
		"results": map[string]any{
			"data": result,
		},
	}, nil
}

func runMongoWrite(ctx context.Context, coll *mongo.Collection, p mongoWriteParsed) (map[string]any, error) {
	switch p.op {
	case "insertOne":
		res, err := coll.InsertOne(ctx, p.doc)
		if err != nil {
			return nil, err
		}
		return map[string]any{"inserted_id": fmt.Sprint(res.InsertedID)}, nil
	case "insertMany":
		res, err := coll.InsertMany(ctx, p.docs)
		if err != nil {
			return nil, err
		}
		ids := make([]string, len(res.InsertedIDs))
		for i, id := range res.InsertedIDs {
			ids[i] = fmt.Sprint(id)
		}
		return map[string]any{"inserted_ids": ids}, nil
	case "updateOne":
		res, err := coll.UpdateOne(ctx, p.filter, p.update)
		if err != nil {
			return nil, err
		}
		return map[string]any{"matched_count": res.MatchedCount, "modified_count": res.ModifiedCount}, nil
	case "updateMany":
		res, err := coll.UpdateMany(ctx, p.filter, p.update)
		if err != nil {
			return nil, err
		}
		return map[string]any{"matched_count": res.MatchedCount, "modified_count": res.ModifiedCount}, nil
	case "replaceOne":
		res, err := coll.ReplaceOne(ctx, p.filter, p.doc)
		if err != nil {
			return nil, err
		}
		return map[string]any{"matched_count": res.MatchedCount, "modified_count": res.ModifiedCount}, nil
	case "deleteOne":
		res, err := coll.DeleteOne(ctx, p.filter)
		if err != nil {
			return nil, err
		}
		return map[string]any{"deleted_count": res.DeletedCount}, nil
	case "deleteMany":
		res, err := coll.DeleteMany(ctx, p.filter)
		if err != nil {
			return nil, err
		}
		return map[string]any{"deleted_count": res.DeletedCount}, nil
	case "aggregate":
		cursor, err := coll.Aggregate(ctx, p.pipeline)
		if err != nil {
			return nil, err
		}
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			// Drain any output from $merge/$out with whenMatched pipeline stages; discarded here
			// since a write-oriented pipeline's point is the side effect, not a result set.
		}
		if err := cursor.Err(); err != nil {
			return nil, err
		}
		return map[string]any{"acknowledged": true}, nil
	default:
		return nil, fmt.Errorf("unsupported mongo write op %q", p.op)
	}
}

type mongoWriteParsed struct {
	collection string
	op         string
	filter     bson.M
	update     bson.M
	doc        bson.M
	docs       []any
	pipeline   bson.A
}

// mongoWriteCallRe matches `db.COLLECTION.OP(ARGS)` shell-shape calls for every write op this
// package can run — same shape as mongoFindRe/mongoAggRe in mongo.go, just covering write ops
// instead of find/aggregate. ARGS is split into individual JSON arguments below.
var mongoWriteCallRe = regexp.MustCompile(`(?is)^\s*db\.([a-zA-Z0-9_]+)\.(insertOne|insertMany|updateOne|updateMany|replaceOne|deleteOne|deleteMany|aggregate)\s*\((.*)\)\s*;?\s*$`)

// parseMongoWriteStatement parses a dispatched write statement into a driver call. It does not
// classify or reject any operation by shape or content — that decision was already made by Curlix
// before this call was dispatched to db_execute_write; this function's only job is turning the
// statement text into the matching mongo-driver call.
func parseMongoWriteStatement(stmt string) (mongoWriteParsed, error) {
	stmt = strings.TrimSpace(stmt)
	if stmt == "" {
		return mongoWriteParsed{}, errEmptyQuery
	}
	if m := mongoWriteCallRe.FindStringSubmatch(stmt); len(m) == 4 {
		collection, op, args := m[1], m[2], strings.TrimSpace(m[3])
		parsed := mongoWriteParsed{collection: collection, op: op}
		switch op {
		case "insertOne":
			doc := bson.M{}
			if err := bson.UnmarshalExtJSON([]byte(args), false, &doc); err != nil {
				return mongoWriteParsed{}, fmt.Errorf("invalid insertOne document: %w", err)
			}
			parsed.doc = doc
		case "insertMany":
			var docs []any
			if err := json.Unmarshal([]byte(args), &docs); err != nil {
				return mongoWriteParsed{}, fmt.Errorf("invalid insertMany documents: %w", err)
			}
			parsed.docs = docs
		case "updateOne", "updateMany":
			filter, update, err := splitTwoJSONArgs(args)
			if err != nil {
				return mongoWriteParsed{}, fmt.Errorf("invalid %s arguments: %w", op, err)
			}
			parsed.filter, parsed.update = filter, update
		case "replaceOne":
			filter, doc, err := splitTwoJSONArgs(args)
			if err != nil {
				return mongoWriteParsed{}, fmt.Errorf("invalid replaceOne arguments: %w", err)
			}
			parsed.filter, parsed.doc = filter, doc
		case "deleteOne", "deleteMany":
			filter := bson.M{}
			if args != "" {
				if err := bson.UnmarshalExtJSON([]byte(args), false, &filter); err != nil {
					return mongoWriteParsed{}, fmt.Errorf("invalid %s filter: %w", op, err)
				}
			}
			parsed.filter = filter
		case "aggregate":
			pipeline := bson.A{}
			if err := bson.UnmarshalExtJSON([]byte(args), false, &pipeline); err != nil {
				return mongoWriteParsed{}, fmt.Errorf("invalid aggregate pipeline: %w", err)
			}
			parsed.pipeline = pipeline
		}
		return parsed, nil
	}
	// JSON fallback: {"collection":"c","op":"updateOne","filter":{},"update":{}}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stmt), &raw); err == nil {
		var collection, op string
		if b, ok := raw["collection"]; ok {
			_ = json.Unmarshal(b, &collection)
		}
		if b, ok := raw["op"]; ok {
			_ = json.Unmarshal(b, &op)
		}
		if collection == "" || op == "" {
			return mongoWriteParsed{}, fmt.Errorf("mongo write JSON statement requires collection and op")
		}
		parsed := mongoWriteParsed{collection: collection, op: op}
		if b, ok := raw["filter"]; ok {
			filter := bson.M{}
			if err := json.Unmarshal(b, &filter); err != nil {
				return mongoWriteParsed{}, err
			}
			parsed.filter = filter
		}
		if b, ok := raw["update"]; ok {
			update := bson.M{}
			if err := json.Unmarshal(b, &update); err != nil {
				return mongoWriteParsed{}, err
			}
			parsed.update = update
		}
		if b, ok := raw["document"]; ok {
			doc := bson.M{}
			if err := json.Unmarshal(b, &doc); err != nil {
				return mongoWriteParsed{}, err
			}
			parsed.doc = doc
		}
		if b, ok := raw["documents"]; ok {
			var docs []any
			if err := json.Unmarshal(b, &docs); err != nil {
				return mongoWriteParsed{}, err
			}
			parsed.docs = docs
		}
		if b, ok := raw["pipeline"]; ok {
			var pipeline bson.A
			if err := json.Unmarshal(b, &pipeline); err != nil {
				return mongoWriteParsed{}, err
			}
			parsed.pipeline = pipeline
		}
		return parsed, nil
	}
	return mongoWriteParsed{}, errUnsupportedMongoWrite
}

// splitTwoJSONArgs splits a "{...}, {...}" argument list (updateOne/updateMany/replaceOne's
// filter+update/replacement pair) into its two top-level JSON values by brace-depth scanning, since
// a naive split on "," would break on any comma inside either object.
func splitTwoJSONArgs(args string) (bson.M, bson.M, error) {
	idx := -1
	depth := 0
	inStr := false
	var strQuote byte
	for i := 0; i < len(args); i++ {
		c := args[i]
		switch {
		case inStr:
			if c == '\\' {
				i++
				continue
			}
			if c == strQuote {
				inStr = false
			}
		case c == '"' || c == '\'':
			inStr = true
			strQuote = c
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
		case c == ',' && depth == 0:
			idx = i
		}
		if idx != -1 {
			break
		}
	}
	if idx == -1 {
		return nil, nil, fmt.Errorf("expected two comma-separated JSON arguments")
	}
	first := strings.TrimSpace(args[:idx])
	second := strings.TrimSpace(args[idx+1:])
	a := bson.M{}
	if err := bson.UnmarshalExtJSON([]byte(first), false, &a); err != nil {
		return nil, nil, err
	}
	b := bson.M{}
	if err := bson.UnmarshalExtJSON([]byte(second), false, &b); err != nil {
		return nil, nil, err
	}
	return a, b, nil
}

var errUnsupportedMongoWrite = fmt.Errorf("unsupported mongo write statement shape")
