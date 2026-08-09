//go:build querystudio

package dbquery

import (
	"context"
	"testing"
	"time"
)

func TestParseMongoWriteStatementInsertOne(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.users.insertOne({"name":"alice"})`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "insertOne" || p.doc["name"] != "alice" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoWriteStatementInsertMany(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.users.insertMany([{"name":"a"},{"name":"b"}])`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "insertMany" || len(p.docs) != 2 {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoWriteStatementUpdateOne(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.users.updateOne({"_id":1}, {"$set":{"name":"bob"}})`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "updateOne" {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.filter["_id"] == nil || p.update["$set"] == nil {
		t.Fatalf("expected filter and update parsed, got %+v", p)
	}
}

func TestParseMongoWriteStatementUpdateManyWithNestedCommas(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.orders.updateMany({"status":{"$in":["a","b"]}}, {"$set":{"x":1,"y":2}})`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "orders" || p.op != "updateMany" {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.filter["status"] == nil {
		t.Fatalf("expected nested-comma filter parsed correctly, got %+v", p.filter)
	}
}

func TestParseMongoWriteStatementReplaceOne(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.users.replaceOne({"_id":1}, {"name":"carol"})`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "replaceOne" || p.doc["name"] != "carol" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoWriteStatementDeleteOne(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.users.deleteOne({"_id":1})`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "deleteOne" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoWriteStatementDeleteMany(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.users.deleteMany({})`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "deleteMany" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoWriteStatementAggregateMerge(t *testing.T) {
	p, err := parseMongoWriteStatement(`db.orders.aggregate([{"$merge":{"into":"target"}}])`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "orders" || p.op != "aggregate" || len(p.pipeline) != 1 {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoWriteStatementJSONFallback(t *testing.T) {
	p, err := parseMongoWriteStatement(`{"collection":"users","op":"updateOne","filter":{"_id":1},"update":{"$set":{"x":1}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "updateOne" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoWriteStatementEmpty(t *testing.T) {
	if _, err := parseMongoWriteStatement(""); err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery, got %v", err)
	}
}

func TestParseMongoWriteStatementUnsupportedShape(t *testing.T) {
	if _, err := parseMongoWriteStatement("not a mongo write statement"); err == nil {
		t.Fatal("expected an error for an unsupported statement shape")
	}
}

func TestParseMongoWriteStatementInvalidJSON(t *testing.T) {
	if _, err := parseMongoWriteStatement(`db.users.insertOne({not valid json})`); err == nil {
		t.Fatal("expected an error for invalid JSON")
	}
}

func TestSplitTwoJSONArgs(t *testing.T) {
	a, b, err := splitTwoJSONArgs(`{"a":1}, {"b":2}`)
	if err != nil {
		t.Fatal(err)
	}
	if a["a"] == nil || b["b"] == nil {
		t.Fatalf("unexpected split: a=%+v b=%+v", a, b)
	}
}

func TestSplitTwoJSONArgsMissingSecond(t *testing.T) {
	if _, _, err := splitTwoJSONArgs(`{"a":1}`); err == nil {
		t.Fatal("expected an error when only one argument is present")
	}
}

func TestExecuteRejectsEnforceReadOnlyAndWriteTogether(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "postgres", "db", "SELECT 1", Options{EnforceReadOnly: true, Write: true})
	if err == nil {
		t.Fatal("expected an error when EnforceReadOnly and Write are both set")
	}
}

func TestExecuteWriteRejectsSnowflake(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "snowflake", "db", "INSERT INTO t VALUES (1)", Options{Write: true, Timeout: time.Millisecond})
	if err == nil {
		t.Fatal("expected an error for unsupported write db_type")
	}
}

func TestExecuteWriteDoesNotClassifyStatement(t *testing.T) {
	// Write:true must not run enforceReadOnlySQL/enforceReadOnlyMongo at all — any rejection here
	// should come from the empty-target dial failure, not from statement classification.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "postgres", "db", "DELETE FROM t", Options{Write: true, Timeout: time.Millisecond})
	if err == nil {
		t.Fatal("expected a dial/context error, not a policy rejection")
	}
}
