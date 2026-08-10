//go:build querystudio

package dbquery

import (
	"context"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// unreachableMongoCollection returns a *mongo.Collection bound to a host nothing listens on.
// mongo.Connect itself never dials (it's lazy), so this succeeds immediately; the actual
// dial/server-selection failure surfaces on the first real operation, which is exactly what
// exercises runMongoWrite's per-op error branches hermetically (no real MongoDB needed).
func unreachableMongoCollection(t *testing.T) *mongo.Collection {
	t.Helper()
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://127.0.0.1:1/db").SetConnectTimeout(15*time.Second))
	if err != nil {
		t.Fatalf("mongo.Connect (lazy, should not dial): %v", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client.Database("db").Collection("c")
}

func shortCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func TestRunMongoWriteInsertOneServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "insertOne", doc: bson.M{"a": 1}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteInsertManyServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "insertMany", docs: []any{bson.M{"a": 1}}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteUpdateOneServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "updateOne", filter: bson.M{"_id": 1}, update: bson.M{"$set": bson.M{"x": 1}}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteUpdateManyServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "updateMany", filter: bson.M{}, update: bson.M{"$set": bson.M{"x": 1}}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteReplaceOneServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "replaceOne", filter: bson.M{"_id": 1}, doc: bson.M{"a": 1}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteDeleteOneServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "deleteOne", filter: bson.M{"_id": 1}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteDeleteManyServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "deleteMany", filter: bson.M{}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteAggregateServerSelectionError(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(shortCtx(t), coll, mongoWriteParsed{op: "aggregate", pipeline: bson.A{bson.M{"$match": bson.M{}}}})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestRunMongoWriteUnsupportedOp(t *testing.T) {
	coll := unreachableMongoCollection(t)
	_, err := runMongoWrite(context.Background(), coll, mongoWriteParsed{op: "bogusOp"})
	if err == nil {
		t.Fatal("expected an error for an unsupported mongo write op")
	}
}

// TestExecuteWriteMongoMissingHost covers executeWriteMongo's own host guard, reached via
// Execute(..., Options{Write:true}) for db_type "mongo".
func TestExecuteWriteMongoMissingHost(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "mongo", "db", `db.users.insertOne({"a":1})`, Options{Write: true})
	if err == nil {
		t.Fatal("expected an error when mongo target has no host")
	}
}

// TestExecuteWriteMongoBadStatementNeverDials covers the parse failure path in executeWriteMongo,
// which runs before any dial attempt.
func TestExecuteWriteMongoBadStatementNeverDials(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "mongo", "db", "not a write statement", Options{Write: true})
	if err == nil {
		t.Fatal("expected a parse error for an unsupported mongo write statement shape")
	}
}

// TestExecuteWriteMongoDialsWithCancelledContext exercises executeWriteMongo's mongo.Connect/dial
// path (URI building with creds, ApplyURI) hermetically via an already-cancelled context.
func TestExecuteWriteMongoDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1", User: "u", Password: "p"}, "mongo", "db", `db.users.insertOne({"a":1})`, Options{Write: true, Timeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("expected an error from a cancelled context during mongo write dial")
	}
}

func TestExecuteWriteSQLEmptyStatement(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "postgres", "db", "  ", Options{Write: true})
	if err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery, got %v", err)
	}
}

func TestExecuteWriteSQLMissingHost(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "mysql", "db", "UPDATE t SET x=1", Options{Write: true})
	if err == nil {
		t.Fatal("expected an error when mysql write target has no host")
	}
}
