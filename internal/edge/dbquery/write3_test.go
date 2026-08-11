package dbquery

import (
	"context"
	"testing"
	"time"
)

// TestExecuteWriteSQLPostgresDialsWithCancelledContext exercises executeWriteSQL's postgres branch
// (sslmode default, pgx driver aliasing) — the mysql branch is already covered by
// TestExecuteWriteSQLMissingHost / TestExecuteWriteDoesNotClassifyStatement.
func TestExecuteWriteSQLPostgresDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "postgres", "db", "DELETE FROM t", Options{Write: true})
	if err == nil {
		t.Fatal("expected an error from a cancelled context during postgres write dial")
	}
}

// TestExecuteWriteMongoNoCredsUsesUnauthenticatedURI exercises executeWriteMongo's "user==” &&
// pass==”" branch, which builds a credential-less mongodb:// URI instead of embedding empty creds.
func TestExecuteWriteMongoNoCredsUsesUnauthenticatedURI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "mongo", "db", `db.users.insertOne({"a":1})`, Options{Write: true})
	if err == nil {
		t.Fatal("expected an error from an unreachable host")
	}
}

// TestParseMongoWriteStatementInvalidInsertMany / InvalidUpdateArgs / InvalidDeleteFilter /
// InvalidAggregatePipeline cover parseMongoWriteStatement's per-op invalid-JSON error branches,
// which the happy-path tests in write_test.go don't reach.
func TestParseMongoWriteStatementInvalidInsertMany(t *testing.T) {
	if _, err := parseMongoWriteStatement(`db.users.insertMany(not valid json)`); err == nil {
		t.Fatal("expected an error for invalid insertMany documents")
	}
}

func TestParseMongoWriteStatementInvalidUpdateArgs(t *testing.T) {
	if _, err := parseMongoWriteStatement(`db.users.updateOne({"_id":1})`); err == nil {
		t.Fatal("expected an error for updateOne missing its second argument")
	}
}

func TestParseMongoWriteStatementInvalidReplaceArgs(t *testing.T) {
	if _, err := parseMongoWriteStatement(`db.users.replaceOne({"_id":1})`); err == nil {
		t.Fatal("expected an error for replaceOne missing its second argument")
	}
}

func TestParseMongoWriteStatementInvalidDeleteFilter(t *testing.T) {
	if _, err := parseMongoWriteStatement(`db.users.deleteOne({not valid})`); err == nil {
		t.Fatal("expected an error for invalid deleteOne filter JSON")
	}
}

func TestParseMongoWriteStatementInvalidAggregatePipeline(t *testing.T) {
	if _, err := parseMongoWriteStatement(`db.orders.aggregate([not valid])`); err == nil {
		t.Fatal("expected an error for invalid aggregate pipeline JSON")
	}
}

// TestParseMongoWriteStatementJSONFallbackMissingOp / MissingCollection cover the JSON-fallback
// path's required-fields guard.
func TestParseMongoWriteStatementJSONFallbackMissingOp(t *testing.T) {
	if _, err := parseMongoWriteStatement(`{"collection":"users"}`); err == nil {
		t.Fatal("expected an error when op is missing")
	}
}

func TestParseMongoWriteStatementJSONFallbackMissingCollection(t *testing.T) {
	if _, err := parseMongoWriteStatement(`{"op":"updateOne"}`); err == nil {
		t.Fatal("expected an error when collection is missing")
	}
}

// TestParseMongoWriteStatementJSONFallbackAllFields exercises every optional-field branch of the
// JSON-fallback path (filter/update/document/documents/pipeline) in one call.
func TestParseMongoWriteStatementJSONFallbackAllFields(t *testing.T) {
	stmt := `{"collection":"users","op":"custom","filter":{"a":1},"update":{"$set":{"b":1}},"document":{"c":1},"documents":[{"d":1}],"pipeline":[{"$match":{}}]}`
	p, err := parseMongoWriteStatement(stmt)
	if err != nil {
		t.Fatal(err)
	}
	if p.filter["a"] == nil || p.update["$set"] == nil || p.doc["c"] == nil || len(p.docs) != 1 || len(p.pipeline) != 1 {
		t.Fatalf("expected every optional field parsed, got %+v", p)
	}
}

func TestParseMongoWriteStatementJSONFallbackInvalidFilter(t *testing.T) {
	if _, err := parseMongoWriteStatement(`{"collection":"users","op":"updateOne","filter":"not-an-object"}`); err == nil {
		t.Fatal("expected an error for invalid filter type")
	}
}

func TestParseMongoWriteStatementJSONFallbackInvalidUpdate(t *testing.T) {
	if _, err := parseMongoWriteStatement(`{"collection":"users","op":"updateOne","update":"not-an-object"}`); err == nil {
		t.Fatal("expected an error for invalid update type")
	}
}

func TestParseMongoWriteStatementJSONFallbackInvalidDocument(t *testing.T) {
	if _, err := parseMongoWriteStatement(`{"collection":"users","op":"insertOne","document":"not-an-object"}`); err == nil {
		t.Fatal("expected an error for invalid document type")
	}
}

func TestParseMongoWriteStatementJSONFallbackInvalidDocuments(t *testing.T) {
	if _, err := parseMongoWriteStatement(`{"collection":"users","op":"insertMany","documents":"not-an-array"}`); err == nil {
		t.Fatal("expected an error for invalid documents type")
	}
}

func TestParseMongoWriteStatementJSONFallbackInvalidPipeline(t *testing.T) {
	if _, err := parseMongoWriteStatement(`{"collection":"users","op":"aggregate","pipeline":"not-an-array"}`); err == nil {
		t.Fatal("expected an error for invalid pipeline type")
	}
}

// TestSplitTwoJSONArgsInvalidFirst / InvalidSecond cover splitTwoJSONArgs' two UnmarshalExtJSON
// error branches, distinct from TestSplitTwoJSONArgsMissingSecond's "no comma found" branch.
func TestSplitTwoJSONArgsInvalidFirst(t *testing.T) {
	if _, _, err := splitTwoJSONArgs(`{not valid}, {"b":2}`); err == nil {
		t.Fatal("expected an error for an invalid first JSON argument")
	}
}

func TestSplitTwoJSONArgsInvalidSecond(t *testing.T) {
	if _, _, err := splitTwoJSONArgs(`{"a":1}, {not valid}`); err == nil {
		t.Fatal("expected an error for an invalid second JSON argument")
	}
}

// TestSplitTwoJSONArgsHandlesEscapedQuotesInStrings exercises the inStr/backslash-escape branch of
// splitTwoJSONArgs' brace-depth scanner (a string value containing an escaped quote must not
// prematurely end the "in string" state and misparse a comma inside it).
func TestSplitTwoJSONArgsHandlesEscapedQuotesInStrings(t *testing.T) {
	a, b, err := splitTwoJSONArgs(`{"note":"a \"quoted, comma\" value"}, {"$set":{"x":1}}`)
	if err != nil {
		t.Fatal(err)
	}
	if a["note"] == nil || b["$set"] == nil {
		t.Fatalf("unexpected split: a=%+v b=%+v", a, b)
	}
}
