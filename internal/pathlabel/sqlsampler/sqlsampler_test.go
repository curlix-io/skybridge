package sqlsampler

import (
	"context"
	"database/sql/driver"
	"testing"
)

func TestSample_ReturnsNonNullValues(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setResult(`SELECT "email" FROM "users" WHERE "email" IS NOT NULL LIMIT 3`, []string{"email"},
		[][]driver.Value{{"alice@example.com"}, {"bob@example.com"}})

	s := New(db, "postgres")
	samples, ok := s.Sample(context.Background(), "org:postgres:appdb:users", "email", 3)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(samples) != 2 || samples[0] != "alice@example.com" || samples[1] != "bob@example.com" {
		t.Fatalf("unexpected samples: %v", samples)
	}
}

func TestSample_MySQLUsesBacktickQuoting(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setResult("SELECT `email` FROM `users` WHERE `email` IS NOT NULL LIMIT 2", []string{"email"},
		[][]driver.Value{{"a@b.com"}})

	s := New(db, "mysql")
	samples, ok := s.Sample(context.Background(), "org:mysql:appdb:users", "email", 2)
	if !ok || len(samples) != 1 {
		t.Fatalf("expected 1 sample via backtick-quoted query, got ok=%v samples=%v", ok, samples)
	}
}

func TestSample_ReturnsFalseOnBadObjectID(t *testing.T) {
	db, _ := registerFakeDB()
	defer db.Close()
	s := New(db, "postgres")
	_, ok := s.Sample(context.Background(), "too:short", "email", 5)
	if ok {
		t.Fatal("expected ok=false for an ObjectID with fewer than 4 colon-separated segments")
	}
}

func TestSample_ReturnsFalseOnEmptyFieldPathOrMaxSamples(t *testing.T) {
	db, _ := registerFakeDB()
	defer db.Close()
	s := New(db, "postgres")
	if _, ok := s.Sample(context.Background(), "org:postgres:appdb:users", "", 5); ok {
		t.Fatal("expected ok=false for empty fieldPath")
	}
	if _, ok := s.Sample(context.Background(), "org:postgres:appdb:users", "email", 0); ok {
		t.Fatal("expected ok=false for maxSamples<=0")
	}
}

func TestSample_ReturnsFalseOnQueryError(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setFail(`SELECT "email" FROM "users" WHERE "email" IS NOT NULL LIMIT 5`)

	s := New(db, "postgres")
	_, ok := s.Sample(context.Background(), "org:postgres:appdb:users", "email", 5)
	if ok {
		t.Fatal("expected ok=false when the underlying query fails")
	}
}

func TestSample_ReturnsFalseOnEmptyResult(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setResult(`SELECT "email" FROM "users" WHERE "email" IS NOT NULL LIMIT 5`, []string{"email"}, nil)

	s := New(db, "postgres")
	_, ok := s.Sample(context.Background(), "org:postgres:appdb:users", "email", 5)
	if ok {
		t.Fatal("expected ok=false when the query succeeds but returns zero rows")
	}
}

func TestSample_SkipsNullValues(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setResult(`SELECT "phone" FROM "users" WHERE "phone" IS NOT NULL LIMIT 5`, []string{"phone"},
		[][]driver.Value{{"555-0100"}, {nil}, {"555-0101"}})

	s := New(db, "postgres")
	samples, ok := s.Sample(context.Background(), "org:postgres:appdb:users", "phone", 5)
	if !ok || len(samples) != 2 {
		t.Fatalf("expected 2 non-null samples, got ok=%v samples=%v", ok, samples)
	}
}

func TestListColumns_UsesDollarPlaceholdersFirst(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setResult("SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2",
		[]string{"column_name"}, [][]driver.Value{{"id"}, {"email"}})

	s := New(db, "postgres")
	cols, err := s.ListColumns(context.Background(), "public", "users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cols) != 2 || cols[0] != "id" || cols[1] != "email" {
		t.Fatalf("unexpected columns: %v", cols)
	}
}

func TestListColumns_FallsBackToQuestionMarkPlaceholders(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setFail("SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2")
	fd.setResult("SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?",
		[]string{"column_name"}, [][]driver.Value{{"id"}})

	s := New(db, "mysql")
	cols, err := s.ListColumns(context.Background(), "appdb", "users")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cols) != 1 || cols[0] != "id" {
		t.Fatalf("unexpected columns: %v", cols)
	}
}

func TestListColumns_PropagatesErrorWhenBothPlaceholderStylesFail(t *testing.T) {
	db, fd := registerFakeDB()
	defer db.Close()
	fd.setFail("SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2")
	fd.setFail("SELECT column_name FROM information_schema.columns WHERE table_schema = ? AND table_name = ?")

	s := New(db, "mysql")
	if _, err := s.ListColumns(context.Background(), "appdb", "users"); err == nil {
		t.Fatal("expected an error when both placeholder styles fail")
	}
}
