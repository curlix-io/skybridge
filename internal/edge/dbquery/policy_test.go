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
		`db.orders.aggregate([{"$merge":{"into":"target"}}])`,
		`db.orders.aggregate([{"$out":"target"}])`,
	} {
		if err := enforceReadOnlyMongo(s); err == nil {
			t.Errorf("expected %q to be blocked", s)
		}
	}
}

// TestEnforceReadOnlySQLBlocksCommentAndCTEBypass is a regression test: isWriteSQL used to check
// only whether the trimmed statement started with a write keyword, so a leading comment or a
// data-modifying CTE slipped through untouched.
func TestEnforceReadOnlySQLBlocksCommentAndCTEBypass(t *testing.T) {
	for _, q := range []string{
		"-- x\nDELETE FROM users",
		"/* x */ DELETE FROM users",
		"WITH d AS (DELETE FROM users RETURNING id) SELECT * FROM d",
		"WITH d AS (UPDATE users SET x=1 RETURNING id) SELECT * FROM d",
	} {
		if err := enforceReadOnlySQL(q); err == nil {
			t.Errorf("expected %q to be blocked", q)
		}
	}
}

// TestEnforceReadOnlySQLAllowsEscapedQuoteInLiteral covers stripSQLNoise's doubled single-quote
// (”) escape handling inside a string literal — without it, the literal's closing quote would be
// misdetected mid-string and the keyword scan could run over raw (unstripped) SQL text.
func TestEnforceReadOnlySQLAllowsEscapedQuoteInLiteral(t *testing.T) {
	if err := enforceReadOnlySQL(`SELECT * FROM t WHERE note = 'it''s fine, no DELETE here'`); err != nil {
		t.Fatalf("expected escaped-quote literal to be allowed, got %v", err)
	}
}

func TestEnforceReadOnlySQLAllowsLiteralsContainingKeywords(t *testing.T) {
	for _, q := range []string{
		"SELECT * FROM tickets WHERE note = 'please delete this ticket'",
		"-- update the cache before reading\nSELECT 1",
	} {
		if err := enforceReadOnlySQL(q); err != nil {
			t.Errorf("expected %q to be allowed, got %v", q, err)
		}
	}
}

func TestEnforceReadOnlyCypherAllowsReads(t *testing.T) {
	for _, q := range []string{
		"MATCH (n:Host) RETURN n LIMIT 10",
		"MATCH (n)-[r]->(m) WHERE n.name = 'db1' RETURN n, r, m",
		"CALL db.labels()",
		"MATCH (n) RETURN count(n)",
	} {
		if err := enforceReadOnlyCypher(q); err != nil {
			t.Errorf("expected %q to be allowed, got %v", q, err)
		}
	}
}

func TestEnforceReadOnlyCypherBlocksWrites(t *testing.T) {
	for _, q := range []string{
		"CREATE (n:Host {name: 'x'})",
		"MATCH (n) MERGE (n)-[:LINKS_TO]->(m)",
		"MATCH (n) DELETE n",
		"MATCH (n) DETACH DELETE n",
		"MATCH (n) SET n.x = 1",
		"MATCH (n) REMOVE n.x",
		"DROP INDEX ON :Host(name)",
		"LOAD CSV FROM 'file:///x.csv' AS row CREATE (n:Host {name: row[0]})",
		"CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DELETE n', {})",
		"CALL dbms.setConfigValue('x', 'y')",
	} {
		if err := enforceReadOnlyCypher(q); err == nil {
			t.Errorf("expected %q to be blocked", q)
		}
	}
}
