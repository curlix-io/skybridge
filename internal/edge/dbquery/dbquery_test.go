//go:build querystudio

package dbquery

import "testing"

func TestResolveTarget(t *testing.T) {
	targets := []Target{
		{DBType: "postgres", AWSAccountID: "111", DatabaseName: "app", Host: "db:5432"},
		{DBType: "mysql", AWSAccountID: "222", DatabaseName: "shop", Host: "mysql:3306"},
	}
	if _, ok := Resolve(targets, "postgres", "111", "app"); !ok {
		t.Fatal("expected postgres target")
	}
	if _, ok := Resolve(targets, "mysql", "222", "shop"); !ok {
		t.Fatal("expected mysql target")
	}
	if _, ok := Resolve(targets, "postgres", "999", "app"); ok {
		t.Fatal("should not match wrong account")
	}
}

func TestEnforceReadOnlySQL(t *testing.T) {
	if err := enforceReadOnlySQL("SELECT 1"); err != nil {
		t.Fatalf("select allowed: %v", err)
	}
	if err := enforceReadOnlySQL("DELETE FROM t"); err == nil {
		t.Fatal("delete should be blocked")
	}
}

func TestParseMongoStatementFind(t *testing.T) {
	p, err := parseMongoStatement("db.users.find({})")
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "users" || p.op != "find" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestParseMongoStatementAggregate(t *testing.T) {
	p, err := parseMongoStatement(`db.orders.aggregate([{"$match":{"a":1}}])`)
	if err != nil {
		t.Fatal(err)
	}
	if p.collection != "orders" || p.op != "aggregate" {
		t.Fatalf("unexpected parse: %+v", p)
	}
}

func TestMergeWireTargets(t *testing.T) {
	merged := MergeWireTargets([]Target{{DBType: "postgres", DatabaseName: "app", Host: "a:5432"}}, nil)
	if len(merged) != 1 {
		t.Fatalf("expected 1, got %d", len(merged))
	}
}
