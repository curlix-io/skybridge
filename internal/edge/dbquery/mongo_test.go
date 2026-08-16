package dbquery

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestParseMongoStatementEmpty(t *testing.T) {
	if _, err := parseMongoStatement(""); err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery, got %v", err)
	}
	if _, err := parseMongoStatement("   "); err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery for whitespace, got %v", err)
	}
}

// TestParseMongoStatementPing covers the connectivity-check sentinel ("ping", case-insensitive,
// trimmed) — the only statement shape that produces an op with no collection.
func TestParseMongoStatementPing(t *testing.T) {
	for _, stmt := range []string{"ping", "PING", "  Ping  "} {
		p, err := parseMongoStatement(stmt)
		if err != nil {
			t.Fatalf("parseMongoStatement(%q): unexpected error: %v", stmt, err)
		}
		if p.op != "ping" || p.collection != "" {
			t.Fatalf("parseMongoStatement(%q) = %+v, want op=ping with no collection", stmt, p)
		}
	}
}

func TestParseMongoStatementFindWithFilter(t *testing.T) {
	p, err := parseMongoStatement(`db.users.find({"age":{"$gt":21}})`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "find" {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.filter["age"] == nil {
		t.Fatalf("expected filter to be parsed, got %v", p.filter)
	}
}

func TestParseMongoStatementFindInvalidFilter(t *testing.T) {
	if _, err := parseMongoStatement(`db.users.find({not valid json})`); err == nil {
		t.Fatal("expected an error for invalid filter JSON")
	}
}

func TestParseMongoStatementAggregateWithPipeline(t *testing.T) {
	p, err := parseMongoStatement(`db.orders.aggregate([{"$match":{"a":1}}])`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "orders" || p.op != "aggregate" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

// The trailing ".limit(N)" clause is swallowed into the greedy filter capture group by mongoFindRe
// (its required closing "\)" matches the statement's final paren, not the one right after the
// filter), so the optional limit group never matches and `limit` stays 0 — documenting this actual
// behavior rather than the presumably-intended "limit(10)" -> limit:10.
func TestParseMongoStatementLimitSuffixIsNotActuallyParsed(t *testing.T) {
	p, err := parseMongoStatement(`db.users.find({}).limit(10)`)
	if err != nil {
		t.Fatal(err)
	}
	if p.limit != 0 {
		t.Fatalf("expected limit to stay 0 due to the regex quirk, got %d", p.limit)
	}
}

func TestParseMongoStatementAggregateRequiresPipeline(t *testing.T) {
	if _, err := parseMongoStatement(`db.orders.aggregate()`); err == nil {
		t.Fatal("expected an error when aggregate has no pipeline")
	}
}

func TestParseMongoStatementAggregateInvalidPipeline(t *testing.T) {
	if _, err := parseMongoStatement(`db.orders.aggregate([not valid])`); err == nil {
		t.Fatal("expected an error for invalid pipeline JSON")
	}
}

func TestParseMongoStatementJSONFallbackFind(t *testing.T) {
	p, err := parseMongoStatement(`{"collection":"users","filter":{"active":true}}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "find" {
		t.Fatalf("unexpected parse: %+v", p)
	}
	if p.filter["active"] != true {
		t.Fatalf("expected filter parsed, got %v", p.filter)
	}
}

func TestParseMongoStatementJSONFallbackAggregate(t *testing.T) {
	p, err := parseMongoStatement(`{"collection":"orders","pipeline":[{"$match":{"a":1}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "orders" || p.op != "aggregate" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoStatementJSONFallbackMissingCollection(t *testing.T) {
	if _, err := parseMongoStatement(`{"filter":{}}`); err == nil {
		t.Fatal("expected an error when collection is missing")
	}
}

func TestParseMongoStatementJSONFallbackInvalidPipeline(t *testing.T) {
	if _, err := parseMongoStatement(`{"collection":"orders","pipeline":"not-an-array"}`); err == nil {
		t.Fatal("expected an error for invalid pipeline type")
	}
}

func TestParseMongoStatementJSONFallbackInvalidFilter(t *testing.T) {
	if _, err := parseMongoStatement(`{"collection":"users","filter":"not-an-object"}`); err == nil {
		t.Fatal("expected an error for invalid filter type")
	}
}

func TestParseMongoStatementUnsupportedShape(t *testing.T) {
	if _, err := parseMongoStatement("not a mongo statement at all"); err == nil {
		t.Fatal("expected an error for an unsupported statement shape")
	}
}

func TestFlattenBSON(t *testing.T) {
	doc := map[string]any{
		"name":   "alice",
		"age":    int32(30),
		"active": true,
		"nested": bson.M{"x": 1},
		"list":   bson.A{1, 2},
		"empty":  nil,
	}
	out := flattenBSON(doc)
	if out["name"] != "alice" || out["age"] != int32(30) || out["active"] != true {
		t.Fatalf("unexpected scalar flattening: %v", out)
	}
	if _, ok := out["nested"].(string); !ok {
		t.Fatalf("expected bson.M to flatten to a JSON string, got %T", out["nested"])
	}
	if _, ok := out["list"].(string); !ok {
		t.Fatalf("expected bson.A to flatten to a JSON string, got %T", out["list"])
	}
	if out["empty"] != nil {
		t.Fatalf("expected nil preserved, got %v", out["empty"])
	}
}

func TestStringifyBSONFallsBackToFmtSprint(t *testing.T) {
	type custom struct{ X int }
	got := stringifyBSON(custom{X: 1})
	if got != "{1}" {
		t.Fatalf("expected fmt.Sprint fallback, got %v", got)
	}
}
