//go:build querystudio

package studiotransport

import "testing"

func TestParseTargets(t *testing.T) {
	ts := ParseTargets(`[{"db_type":"postgres","host":"a:5432"}]`)
	if len(ts) != 1 || ts[0].DBType != "postgres" {
		t.Fatalf("unexpected targets: %v", ts)
	}
	if got := ParseTargets(""); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
	if got := ParseTargets("not json"); got != nil {
		t.Fatalf("expected nil for invalid JSON, got %v", got)
	}
}
