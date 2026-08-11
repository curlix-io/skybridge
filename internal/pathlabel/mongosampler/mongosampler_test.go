package mongosampler

import (
	"context"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func TestObjectIDParts(t *testing.T) {
	db, coll, ok := objectIDParts("org1:mongo:app:orders")
	if !ok || db != "app" || coll != "orders" {
		t.Fatalf("unexpected parse: db=%q coll=%q ok=%v", db, coll, ok)
	}
	if _, _, ok := objectIDParts("org1:mongo:app"); ok {
		t.Fatal("expected ok=false for too few segments")
	}
	if _, _, ok := objectIDParts(""); ok {
		t.Fatal("expected ok=false for empty ObjectID")
	}
}

func TestMongoQueryPath(t *testing.T) {
	cases := map[string]string{
		"email":         "email",
		"profile.email": "profile.email",
		"tags[]":        "tags",
		"tags[].name":   "tags.name",
		"a.b[].c[].d":   "a.b.c.d",
	}
	for in, want := range cases {
		if got := mongoQueryPath(in); got != want {
			t.Errorf("mongoQueryPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeDoc(t *testing.T) {
	doc := map[string]any{
		"name":    "alice",
		"nested":  bson.M{"email": "a@example.com"},
		"tags":    bson.A{"x", "y"},
		"already": map[string]any{"k": "v"},
	}
	out := normalizeDoc(doc)
	nested, ok := out["nested"].(map[string]any)
	if !ok || nested["email"] != "a@example.com" {
		t.Fatalf("expected bson.M normalized to map[string]any, got %#v", out["nested"])
	}
	tags, ok := out["tags"].([]any)
	if !ok || len(tags) != 2 || tags[0] != "x" {
		t.Fatalf("expected bson.A normalized to []any, got %#v", out["tags"])
	}
}

func TestSampleRejectsBadInput(t *testing.T) {
	s := New(nil)
	if _, ok := s.Sample(context.Background(), "bad-object-id", "email", 5); ok {
		t.Fatal("expected ok=false for a malformed ObjectID")
	}
	if _, ok := s.Sample(context.Background(), "org1:mongo:app:orders", "", 5); ok {
		t.Fatal("expected ok=false for an empty fieldPath")
	}
	if _, ok := s.Sample(context.Background(), "org1:mongo:app:orders", "email", 0); ok {
		t.Fatal("expected ok=false for maxSamples <= 0")
	}
}

// mongo.Connect never dials (it's lazy) — same hermetic pattern internal/edge/dbquery's Mongo tests
// already use — so this exercises Sample's/ListColumns' query path against an unreachable server
// under an immediately-cancelled context, without needing a real MongoDB instance.
func TestSampleAndListColumnsFailFastOnCancelledContext(t *testing.T) {
	client, err := mongo.Connect(context.Background(),
		options.Client().ApplyURI("mongodb://127.0.0.1:1/db").SetConnectTimeout(15*time.Second))
	if err != nil {
		t.Fatalf("mongo.Connect (lazy, should not dial): %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New(client)
	if _, ok := s.Sample(ctx, "org1:mongo:app:orders", "email", 5); ok {
		t.Fatal("expected ok=false against a cancelled context")
	}
	if _, err := s.ListColumns(ctx, "app", "orders"); err == nil {
		t.Fatal("expected an error against a cancelled context")
	}
	if _, err := s.ListTables(ctx, "app"); err == nil {
		t.Fatal("expected an error against a cancelled context")
	}
}
