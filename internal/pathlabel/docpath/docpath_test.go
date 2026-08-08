package docpath

import (
	"reflect"
	"sort"
	"testing"
)

func sortLeaves(leaves []Leaf) []Leaf {
	out := append([]Leaf(nil), leaves...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		if out[i].IsKey != out[j].IsKey {
			return out[i].IsKey
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func TestWalk_NestedKey(t *testing.T) {
	doc := map[string]any{
		"profile": map[string]any{
			"contact": map[string]any{
				"email": "jane@example.com",
			},
		},
	}
	leaves := Walk(doc)
	want := []Leaf{
		{Path: "", Key: "profile", Value: "profile", IsKey: true},
		{Path: "profile", Key: "contact", Value: "contact", IsKey: true},
		{Path: "profile.contact", Key: "email", Value: "email", IsKey: true},
		{Path: "profile.contact.email", Key: "email", Value: "jane@example.com"},
	}
	if !reflect.DeepEqual(sortLeaves(leaves), sortLeaves(want)) {
		t.Fatalf("got %+v, want %+v", leaves, want)
	}
}

func TestWalk_IndexErasure(t *testing.T) {
	doc := map[string]any{
		"messages": []any{
			map[string]any{"content": "hi"},
			map[string]any{"content": "there"},
			map[string]any{"content": "again"},
		},
	}
	leaves := Walk(doc)
	valuePaths := map[string]int{}
	for _, l := range leaves {
		if !l.IsKey {
			valuePaths[l.Path]++
		}
	}
	if got := valuePaths["messages[].content"]; got != 3 {
		t.Fatalf("expected 3 value leaves at messages[].content, got %d (leaves=%+v)", got, leaves)
	}
}

func TestWalk_SameKeyDifferentPath(t *testing.T) {
	doc := map[string]any{
		"order": map[string]any{"total": "100"},
		"user":  map[string]any{"total": "5"},
	}
	leaves := Walk(doc)
	paths := map[string]bool{}
	for _, l := range leaves {
		if !l.IsKey && l.Key == "total" {
			paths[l.Path] = true
		}
	}
	if !paths["order.total"] || !paths["user.total"] {
		t.Fatalf("expected independent paths order.total and user.total, got %+v", leaves)
	}
}

func TestWalk_KeyedByIdentifier(t *testing.T) {
	doc := map[string]any{
		"user@email.com": map[string]any{"balance": "100"},
	}
	leaves := Walk(doc)
	found := false
	for _, l := range leaves {
		if l.IsKey && l.Value == "user@email.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a key-leaf for the PII-bearing key, got %+v", leaves)
	}
}

func TestWalk_ScalarArray(t *testing.T) {
	doc := map[string]any{
		"tags": []any{"a@b.com", "internal"},
	}
	leaves := Walk(doc)
	var values []string
	for _, l := range leaves {
		if !l.IsKey {
			values = append(values, l.Value)
		}
	}
	sort.Strings(values)
	want := []string{"a@b.com", "internal"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("got %v, want %v", values, want)
	}
}

func TestWalk_NonStringLeavesSkipped(t *testing.T) {
	doc := map[string]any{
		"age":    42,
		"active": true,
		"name":   "jane",
	}
	leaves := Walk(doc)
	for _, l := range leaves {
		if !l.IsKey && l.Key != "name" {
			t.Fatalf("non-string value leaf unexpectedly visited: %+v", l)
		}
	}
}

func TestReplace_ValueLeaf(t *testing.T) {
	doc := map[string]any{
		"profile": map[string]any{"email": "jane@example.com"},
	}
	n := Replace(doc, func(l Leaf) bool {
		return !l.IsKey && l.Path == "profile" && l.Key == "email"
	}, func(l Leaf) string {
		return "[REDACTED]"
	})
	if n != 1 {
		t.Fatalf("expected 1 replacement, got %d", n)
	}
	got := doc["profile"].(map[string]any)["email"]
	if got != "[REDACTED]" {
		t.Fatalf("value not replaced, got %v", got)
	}
}

func TestReplace_KeyLeaf(t *testing.T) {
	doc := map[string]any{
		"user@email.com": map[string]any{"balance": "100"},
	}
	n := Replace(doc, func(l Leaf) bool {
		return l.IsKey && l.Value == "user@email.com"
	}, func(l Leaf) string {
		return "[REDACTED_KEY]"
	})
	if n != 1 {
		t.Fatalf("expected 1 replacement, got %d", n)
	}
	if _, stillPresent := doc["user@email.com"]; stillPresent {
		t.Fatalf("old key still present after rename")
	}
	v, ok := doc["[REDACTED_KEY]"]
	if !ok {
		t.Fatalf("renamed key not found; doc=%+v", doc)
	}
	if v.(map[string]any)["balance"] != "100" {
		t.Fatalf("value lost during key rename: %+v", v)
	}
}

func TestReplace_ArrayScalar(t *testing.T) {
	doc := map[string]any{
		"tags": []any{"a@b.com", "internal"},
	}
	n := Replace(doc, func(l Leaf) bool {
		return !l.IsKey && l.Value == "a@b.com"
	}, func(l Leaf) string {
		return "[REDACTED]"
	})
	if n != 1 {
		t.Fatalf("expected 1 replacement, got %d", n)
	}
	tags := doc["tags"].([]any)
	if tags[0] != "[REDACTED]" || tags[1] != "internal" {
		t.Fatalf("unexpected tags after replace: %+v", tags)
	}
}
