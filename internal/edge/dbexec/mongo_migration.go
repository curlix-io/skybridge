package dbexec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/edge/dbquery"
)

// mongoMigrationOptions configures the mongosh shell-out used to apply a Mongo changeset. This
// mirrors solidbase's own execution mechanism today (backend/src/curlix/commands/mongodb —
// QueryExecutor._execute_single_query shells out to mongosh with --eval, since there is no pymongo
// driver call that can run an arbitrary native-JS changeset) — relocating the same subprocess
// pattern to run inside the customer network instead of the SaaS backend host, the same way
// internal/edge/awsexec and internal/edge/k8sexec already shell out to aws-cli/kubectl at the edge.
type mongoMigrationOptions struct {
	MongoshBin string
	Timeout    time.Duration
	MaxStderr  int
}

func (o mongoMigrationOptions) withDefaults() mongoMigrationOptions {
	if o.MongoshBin == "" {
		o.MongoshBin = findMongoshPath()
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	if o.MaxStderr <= 0 {
		o.MaxStderr = 4000
	}
	return o
}

// mongoMigrationMarkerOK / mongoMigrationMarkerErr delimit the eval script's own success/failure
// signal in stdout, distinct from whatever the changeset itself prints.
const (
	mongoMigrationMarkerOK  = "__CURLIX_MIGRATION_OK__"
	mongoMigrationMarkerErr = "__CURLIX_MIGRATION_ERROR__"
)

// runMongoMigration applies script (arbitrary native-JS, exactly the shape solidbase's Mongo
// changesets already use) via mongosh --eval. The script is wrapped so unmodified `db.<collection>`
// calls inside it transparently run against a session-bound `db` when the target supports
// multi-document transactions (replica set / sharded cluster) — commit on success, abort on any
// thrown error. Standalone Mongo servers don't support transactions at all; startTransaction()
// throws immediately there, so the wrapper detects that and falls back to running the script
// without a transaction, matching solidbase's current no-atomicity behavior for that topology
// rather than failing outright.
func runMongoMigration(ctx context.Context, target dbquery.Target, database, script string, opts mongoMigrationOptions) (MigrationResult, error) {
	opts = opts.withDefaults()
	script = strings.TrimSpace(script)
	if script == "" {
		return MigrationResult{}, fmt.Errorf("empty migration script")
	}
	if opts.MongoshBin == "" {
		return MigrationResult{}, fmt.Errorf("mongosh binary not found on edge; cannot apply mongo migration")
	}

	uri := mongoConnectionString(target, database)
	evalScript := wrapMongoMigrationScript(script)

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, opts.MongoshBin, uri, "--norc", "--quiet", "--eval", evalScript, "--authenticationDatabase", "admin")
	cmd.Env = append(os.Environ(), "MONGOSH_DISABLE_TELEMETRY=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	out := stdout.String()
	switch {
	case strings.Contains(out, mongoMigrationMarkerOK):
		return MigrationResult{AppliedStatements: 1}, nil
	case strings.Contains(out, mongoMigrationMarkerErr):
		idx := strings.Index(out, mongoMigrationMarkerErr)
		detail := strings.TrimSpace(out[idx+len(mongoMigrationMarkerErr):])
		return MigrationResult{}, fmt.Errorf("mongo migration failed, changeset rolled back (or ran without transaction on a standalone target): %s", clipMongoOutput(detail, opts.MaxStderr))
	case runCtx.Err() != nil:
		return MigrationResult{}, fmt.Errorf("mongo migration timed out: %w", runCtx.Err())
	default:
		return MigrationResult{}, fmt.Errorf("mongo migration exited without a recognized marker (exit=%v): %s", runErr, clipMongoOutput(stderr.String(), opts.MaxStderr))
	}
}

// wrapMongoMigrationScript wraps an arbitrary changeset in a session/transaction attempt. `db` is
// rebound to a session-bound database handle so unmodified `db.collection.op(...)` calls in the
// changeset run inside the transaction with no changes required to how solidbase authors scripts
// today. startTransaction() throws synchronously on a standalone (non-replica-set) target, which is
// caught and treated as "this target has no transaction support" rather than a changeset failure.
func wrapMongoMigrationScript(script string) string {
	return fmt.Sprintf(`(function() {
  var __origDb = db;
  var __session = __origDb.getMongo().startSession();
  var __useTxn = true;
  try {
    __session.startTransaction();
  } catch (e) {
    __useTxn = false;
  }
  var db = __useTxn ? __session.getDatabase(__origDb.getName()) : __origDb;
  try {
    %s
    if (__useTxn) { __session.commitTransaction(); }
    print(%q);
  } catch (e) {
    if (__useTxn) {
      try { __session.abortTransaction(); } catch (abortErr) {}
    }
    print(%q + (e && e.message ? e.message : String(e)));
  } finally {
    __session.endSession();
  }
})();`, script, mongoMigrationMarkerOK, mongoMigrationMarkerErr)
}

func mongoConnectionString(target dbquery.Target, database string) string {
	host := strings.TrimSpace(target.Host)
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	if target.User == "" && target.Password == "" {
		return fmt.Sprintf("mongodb://%s/%s", host, dbName)
	}
	return fmt.Sprintf("mongodb://%s:%s@%s/%s", urlEscapeMongo(target.User), urlEscapeMongo(target.Password), host, dbName)
}

func urlEscapeMongo(s string) string {
	r := strings.NewReplacer("@", "%40", ":", "%3A", "/", "%2F")
	return r.Replace(s)
}

// findMongoshPath mirrors QueryExecutor._find_mongosh_path's search order (backend
// query_executor.py) — checked common install locations first, falling back to bare "mongosh" on
// PATH so a from-scratch edge image only needs mongosh installed, not pinned to one of these paths.
func findMongoshPath() string {
	candidates := []string{"/usr/local/bin/mongosh", "/usr/bin/mongosh", "/opt/mongosh/bin/mongosh"}
	for _, p := range candidates {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	if _, err := exec.LookPath("mongosh"); err == nil {
		return "mongosh"
	}
	return ""
}

func clipMongoOutput(s string, max int) string {
	s = strings.TrimSpace(s)
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}
