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
