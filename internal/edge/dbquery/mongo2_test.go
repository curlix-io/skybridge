package dbquery

import (
	"reflect"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

// TestNormalizeBSONDoc_ConvertsNamedTypesRecursively covers normalizeBSONDoc/normalizeBSONValue's
// full type-switch: bson.M and bson.A (both nested and top-level) must come out as the plain,
// unnamed map[string]any/[]any types docpath.Walk's type switch actually matches (see the doc
// comment on normalizeBSONDoc) — scalars pass through untouched.
func TestNormalizeBSONDoc_ConvertsNamedTypesRecursively(t *testing.T) {
	doc := map[string]any{
		"top":    bson.M{"nested": bson.M{"leaf": "v"}},
		"arr":    bson.A{bson.M{"x": 1}, "plain"},
		"plain":  []any{bson.M{"y": 2}},
		"scalar": "s",
		"num":    int32(5),
		"nilv":   nil,
	}
	out := normalizeBSONDoc(doc)

	top, ok := out["top"].(map[string]any)
	if !ok {
		t.Fatalf("expected top to become map[string]any, got %T", out["top"])
	}
	nested, ok := top["nested"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested bson.M to become map[string]any, got %T", top["nested"])
	}
	if nested["leaf"] != "v" {
		t.Fatalf("expected leaf value preserved, got %v", nested["leaf"])
	}

	arr, ok := out["arr"].([]any)
	if !ok {
		t.Fatalf("expected arr to become []any, got %T", out["arr"])
	}
	if _, ok := arr[0].(map[string]any); !ok {
		t.Fatalf("expected arr[0] bson.M element to become map[string]any, got %T", arr[0])
	}
	if arr[1] != "plain" {
		t.Fatalf("expected plain string element preserved, got %v", arr[1])
	}

	plainArr, ok := out["plain"].([]any)
	if !ok {
		t.Fatalf("expected plain []any to stay []any, got %T", out["plain"])
	}
	if _, ok := plainArr[0].(map[string]any); !ok {
		t.Fatalf("expected nested bson.M inside plain []any to be converted, got %T", plainArr[0])
	}

	if out["scalar"] != "s" || out["num"] != int32(5) || out["nilv"] != nil {
		t.Fatalf("expected scalars preserved as-is, got %v", out)
	}

	if reflect.TypeOf(out["top"]).Kind() != reflect.Map {
		t.Fatalf("expected map kind, got %v", reflect.TypeOf(out["top"]).Kind())
	}
}

// TestMongoURIPrefersDSNOverHost proves mongoURI uses target.DSN verbatim, without ever
// consulting Host/User/Password, when DSN is set — the case a per-call "connection" override
// (TargetFromOverride) produces for mongo, since a real mongo URI (mongodb+srv://, replica-set
// members, auth params) doesn't survive a host/port/user/pass decomposition.
func TestMongoURIPrefersDSNOverHost(t *testing.T) {
	target := Target{DSN: "mongodb+srv://u:p@cluster0.example.mongodb.net/ignored?replicaSet=rs0", Host: "should-not-be-used:27017", User: "should-not-be-used"}
	uri, dbName, err := mongoURI(target, "app", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri != target.DSN {
		t.Fatalf("expected DSN returned verbatim, got %q", uri)
	}
	if dbName != "app" {
		t.Fatalf("expected database param to win over target.DatabaseName, got %q", dbName)
	}
}

// TestMongoURIFallsBackToHostComposition proves mongoURI still composes a URI from Host/creds
// when DSN is empty — the pre-existing, static-Targets behavior must be unaffected.
func TestMongoURIFallsBackToHostComposition(t *testing.T) {
	target := Target{Host: "mongo.internal:27017", User: "u", Password: "p"}
	uri, dbName, err := mongoURI(target, "", Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if uri != "mongodb://u:p@mongo.internal:27017/" {
		t.Fatalf("unexpected composed URI: %q", uri)
	}
	if dbName != "" {
		t.Fatalf("expected empty database name to fall back to target.DatabaseName (also empty), got %q", dbName)
	}
}

// TestMongoURIMissingHostAndDSN proves mongoURI still fails closed when neither DSN nor Host is
// set — the "mongo target missing host" guard must survive the DSN-preference refactor.
func TestMongoURIMissingHostAndDSN(t *testing.T) {
	if _, _, err := mongoURI(Target{}, "db", Options{}); err == nil {
		t.Fatal("expected an error when target has neither DSN nor Host")
	}
}
