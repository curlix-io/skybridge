//go:build querystudio

package dbquery

import "testing"

func TestEnforceReadOnlySQLAllowsReads(t *testing.T) {
	for _, q := range []string{"SELECT 1", "  select * from t", "WITH x AS (SELECT 1) SELECT * FROM x", "EXPLAIN SELECT 1"} {
		if err := enforceReadOnlySQL(q); err != nil {
			t.Errorf("expected %q to be allowed, got %v", q, err)
		}
	}
}

func TestEnforceReadOnlySQLBlocksWrites(t *testing.T) {
	for _, q := range []string{
		"INSERT INTO t VALUES (1)",
		"update t set x=1",
		"DELETE FROM t",
		"DROP TABLE t",
		"ALTER TABLE t ADD COLUMN x int",
		"CREATE TABLE t (x int)",
		"TRUNCATE t",
		"GRANT ALL ON t TO u",
		"REVOKE ALL ON t FROM u",
	} {
		if err := enforceReadOnlySQL(q); err == nil {
			t.Errorf("expected %q to be blocked", q)
		}
	}
}

func TestEnforceReadOnlyMongoAllowsReads(t *testing.T) {
	for _, s := range []string{"db.users.find({})", "db.orders.aggregate([])", "db.users.countDocuments({})"} {
		if err := enforceReadOnlyMongo(s); err != nil {
			t.Errorf("expected %q to be allowed, got %v", s, err)
		}
	}
}

func TestEnforceReadOnlyMongoBlocksWrites(t *testing.T) {
	for _, s := range []string{
		"db.users.insert({})",
		"db.users.update({}, {})",
		"db.users.delete({})",
		"db.users.remove({})",
		"db.users.drop()",
		"db.users.createIndex({})",
		"db.createCollection('x')",
	} {
		if err := enforceReadOnlyMongo(s); err == nil {
			t.Errorf("expected %q to be blocked", s)
		}
	}
}
