//go:build querystudio

package dbexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/edge/dbquery"
)

func TestMongoMigrationOptionsWithDefaults(t *testing.T) {
	o := mongoMigrationOptions{}.withDefaults()
	if o.Timeout != 60*time.Second {
		t.Fatalf("expected default 60s timeout, got %v", o.Timeout)
	}
	if o.MaxStderr != 4000 {
		t.Fatalf("expected default MaxStderr 4000, got %d", o.MaxStderr)
	}
	if o.MongoshBin == "" {
		// findMongoshPath() ran; on a bare test runner it's typically empty, but this call itself
		// must not panic and must return a value (empty or not) rather than being skipped.
		t.Log("no mongosh found in test environment (expected in CI)")
	}

	o2 := mongoMigrationOptions{MongoshBin: "/custom/mongosh", Timeout: time.Second, MaxStderr: 10}.withDefaults()
	if o2.MongoshBin != "/custom/mongosh" || o2.Timeout != time.Second || o2.MaxStderr != 10 {
		t.Fatalf("expected explicit values preserved, got %+v", o2)
	}
}

func TestRunMongoMigrationRejectsEmptyScript(t *testing.T) {
	_, err := runMongoMigration(context.Background(), dbquery.Target{Host: "h"}, "db", "   ", mongoMigrationOptions{MongoshBin: "/bin/true"})
	if err == nil {
		t.Fatal("expected an error for an empty migration script")
	}
}

// TestRunMongoMigrationRejectsMissingMongoshBinary exercises the "mongosh binary not found" guard
// by clearing PATH so findMongoshPath() (called by withDefaults when MongoshBin=="") can't resolve
// even the bare "mongosh" fallback, regardless of whether the host running this test happens to
// have mongosh installed.
func TestRunMongoMigrationRejectsMissingMongoshBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := runMongoMigration(context.Background(), dbquery.Target{Host: "h"}, "db", "db.x.insertOne({})", mongoMigrationOptions{MongoshBin: ""})
	if err == nil || !strings.Contains(err.Error(), "mongosh binary not found") {
		t.Fatalf("expected a 'mongosh binary not found' error, got %v", err)
	}
}

// TestRunMongoMigrationRunsUnrecognizedBinary points MongoshBin at a real, harmless binary
// (/usr/bin/false) that exits non-zero and prints nothing containing either marker — exercising the
// "exited without a recognized marker" branch hermetically, without needing mongosh installed.
func TestRunMongoMigrationRunsUnrecognizedBinary(t *testing.T) {
	_, err := runMongoMigration(context.Background(), dbquery.Target{Host: "h"}, "db", "db.x.insertOne({})", mongoMigrationOptions{MongoshBin: "/usr/bin/false", Timeout: 5 * time.Second})
	if err == nil {
		t.Fatal("expected an error since /usr/bin/false won't print either marker")
	}
	if !strings.Contains(err.Error(), "without a recognized marker") {
		t.Fatalf("expected 'without a recognized marker' error, got %v", err)
	}
}

// TestRunMongoMigrationTimesOut points MongoshBin at a tiny shell script that ignores its
// arguments and sleeps far longer than the configured timeout, to exercise the runCtx.Err()
// timeout branch hermetically (no real mongosh/server needed).
func TestRunMongoMigrationTimesOut(t *testing.T) {
	scriptPath := filepath.Join(t.TempDir(), "slow-mongosh.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatalf("write test script: %v", err)
	}
	_, err := runMongoMigration(context.Background(), dbquery.Target{Host: "h"}, "db", "db.x.insertOne({})", mongoMigrationOptions{MongoshBin: scriptPath, Timeout: 50 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a timeout error, got %v", err)
	}
}

func TestWrapMongoMigrationScriptEmbedsScriptAndMarkers(t *testing.T) {
	wrapped := wrapMongoMigrationScript("db.x.insertOne({a:1});")
	if !strings.Contains(wrapped, "db.x.insertOne({a:1});") {
		t.Fatal("expected the original script embedded verbatim")
	}
	if !strings.Contains(wrapped, mongoMigrationMarkerOK) || !strings.Contains(wrapped, mongoMigrationMarkerErr) {
		t.Fatal("expected both success and error markers present")
	}
	if !strings.Contains(wrapped, "startTransaction") {
		t.Fatal("expected the transaction-attempt wrapper present")
	}
}

func TestMongoConnectionStringWithCreds(t *testing.T) {
	uri := mongoConnectionString(dbquery.Target{Host: "h:27017", User: "u", Password: "p"}, "mydb")
	if uri != "mongodb://u:p@h:27017/mydb" {
		t.Fatalf("unexpected uri: %q", uri)
	}
}

func TestMongoConnectionStringWithoutCreds(t *testing.T) {
	uri := mongoConnectionString(dbquery.Target{Host: "h:27017"}, "mydb")
	if uri != "mongodb://h:27017/mydb" {
		t.Fatalf("unexpected uri: %q", uri)
	}
}

func TestMongoConnectionStringFallsBackToTargetDatabaseName(t *testing.T) {
	uri := mongoConnectionString(dbquery.Target{Host: "h:27017", DatabaseName: "fallback"}, "")
	if uri != "mongodb://h:27017/fallback" {
		t.Fatalf("unexpected uri: %q", uri)
	}
}

func TestMongoConnectionStringEscapesCredsWithReservedChars(t *testing.T) {
	uri := mongoConnectionString(dbquery.Target{Host: "h:27017", User: "u@x", Password: "p:y/z"}, "db")
	if uri != "mongodb://u%40x:p%3Ay%2Fz@h:27017/db" {
		t.Fatalf("unexpected uri: %q", uri)
	}
}

func TestUrlEscapeMongo(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"a@b":         "a%40b",
		"a:b":         "a%3Ab",
		"a/b":         "a%2Fb",
		"u@ser:pa/ss": "u%40ser%3Apa%2Fss",
	}
	for in, want := range cases {
		if got := urlEscapeMongo(in); got != want {
			t.Errorf("urlEscapeMongo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindMongoshPathReturnsEmptyOrValidPath(t *testing.T) {
	// This just exercises the function; the test environment may or may not have mongosh, so we
	// only assert it doesn't panic and (if non-empty) the result is one of the expected candidates.
	got := findMongoshPath()
	if got == "" {
		return
	}
	valid := map[string]bool{
		"/usr/local/bin/mongosh":   true,
		"/usr/bin/mongosh":         true,
		"/opt/mongosh/bin/mongosh": true,
		"mongosh":                  true,
	}
	if !valid[got] {
		t.Fatalf("unexpected mongosh path: %q", got)
	}
}

func TestClipMongoOutput(t *testing.T) {
	if got := clipMongoOutput("  hello  ", 100); got != "hello" {
		t.Fatalf("expected trimmed short string unchanged, got %q", got)
	}
	if got := clipMongoOutput("hello world", 5); got != "hello" {
		t.Fatalf("expected clipped to 5 chars, got %q", got)
	}
	if got := clipMongoOutput("hello", 0); got != "hello" {
		t.Fatalf("expected max<=0 to mean uncapped, got %q", got)
	}
}
