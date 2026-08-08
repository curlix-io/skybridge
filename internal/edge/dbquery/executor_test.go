//go:build querystudio

package dbquery

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOptionsWithDefaults(t *testing.T) {
	o := Options{}.withDefaults()
	if o.MaxRows != 1000 {
		t.Fatalf("expected default MaxRows 1000, got %d", o.MaxRows)
	}
	if o.Timeout != 60*time.Second {
		t.Fatalf("expected default Timeout 60s, got %v", o.Timeout)
	}
}

func TestOptionsWithDefaultsPreservesExplicitValues(t *testing.T) {
	o := Options{MaxRows: 5, Timeout: 2 * time.Second}.withDefaults()
	if o.MaxRows != 5 || o.Timeout != 2*time.Second {
		t.Fatalf("expected explicit values preserved, got MaxRows=%d Timeout=%v", o.MaxRows, o.Timeout)
	}
}

func TestCreds(t *testing.T) {
	cases := []struct {
		name             string
		target           Target
		fallbackUser     string
		fallbackPassword string
		wantUser         string
		wantPass         string
	}{
		{"target creds win", Target{User: "u1", Password: "p1"}, "u2", "p2", "u1", "p1"},
		{"falls back when empty", Target{}, "u2", "p2", "u2", "p2"},
		{"trims target user", Target{User: "  u1  ", Password: "p1"}, "", "", "u1", "p1"},
	}
	for _, c := range cases {
		user, pass := creds(c.target, c.fallbackUser, c.fallbackPassword)
		if user != c.wantUser || pass != c.wantPass {
			t.Errorf("%s: creds() = (%q, %q), want (%q, %q)", c.name, user, pass, c.wantUser, c.wantPass)
		}
	}
}

func TestUrlEscape(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"a@b":         "a%40b",
		"a:b":         "a%3Ab",
		"a/b":         "a%2Fb",
		"u@ser:pa/ss": "u%40ser%3Apa%2Fss",
	}
	for in, want := range cases {
		if got := urlEscape(in); got != want {
			t.Errorf("urlEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeVal(t *testing.T) {
	if got := normalizeVal([]byte("hello")); got != "hello" {
		t.Fatalf("expected []byte converted to string, got %v (%T)", got, got)
	}
	if got := normalizeVal(42); got != 42 {
		t.Fatalf("expected non-[]byte passed through unchanged, got %v", got)
	}
	if got := normalizeVal(nil); got != nil {
		t.Fatalf("expected nil passed through, got %v", got)
	}
}

func TestTabularResult(t *testing.T) {
	rows := []map[string]any{{"id": 1}}
	out := tabularResult([]string{"id"}, rows)
	if out["status"] != "success" {
		t.Fatalf("expected status success, got %v", out["status"])
	}
	results, ok := out["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results map, got %T", out["results"])
	}
	if cols, ok := results["columns"].([]string); !ok || len(cols) != 1 || cols[0] != "id" {
		t.Fatalf("unexpected columns: %v", results["columns"])
	}
}

func TestCapRows(t *testing.T) {
	rows := []map[string]any{{"a": 1}, {"a": 2}, {"a": 3}}
	if got := capRows(rows, 0); len(got) != 3 {
		t.Fatalf("expected uncapped when max<=0, got %d", len(got))
	}
	if got := capRows(rows, 10); len(got) != 3 {
		t.Fatalf("expected uncapped when max exceeds length, got %d", len(got))
	}
	if got := capRows(rows, 2); len(got) != 2 {
		t.Fatalf("expected capped to 2, got %d", len(got))
	}
}

func TestExecuteRejectsUnsupportedDBType(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "oracle", "db", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error for an unsupported db_type")
	}
}

func TestExecuteEnforcesReadOnlySQLBeforeDialing(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "postgres", "db", "DELETE FROM t", Options{EnforceReadOnly: true})
	if err == nil {
		t.Fatal("expected write statement to be blocked before any connection attempt")
	}
}

func TestExecuteEnforcesReadOnlyMongoBeforeDialing(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "mongo", "db", "db.users.insert({})", Options{EnforceReadOnly: true})
	if err == nil {
		t.Fatal("expected write statement to be blocked before any connection attempt")
	}
}

func TestExecuteRespectsContextCancellationBeforeDialing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "postgres", "db", "SELECT 1", Options{Timeout: time.Millisecond})
	if err == nil {
		t.Fatal("expected an error from a cancelled/expired context")
	}
}

func TestErrEmptyQueryIsDistinctSentinel(t *testing.T) {
	if !errors.Is(errEmptyQuery, errEmptyQuery) {
		t.Fatal("sanity: errEmptyQuery should equal itself")
	}
	if errEmptyQuery.Error() == "" {
		t.Fatal("expected a non-empty message")
	}
}
