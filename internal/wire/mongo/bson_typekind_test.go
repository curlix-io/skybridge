package mongo

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// ebool/eint64/edouble/edatetime/eobjectid build BSON elements for the scalar types Gap B routes
// through masking (see bsonTypeKind) — estring/eint32 already exist in mongo_test.go.
func ebool(name string, v bool) []byte {
	e := []byte{bsonBool}
	e = append(e, cstr(name)...)
	if v {
		return append(e, 0x01)
	}
	return append(e, 0x00)
}

func eint64(name string, v int64) []byte {
	e := []byte{bsonInt64}
	e = append(e, cstr(name)...)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(v))
	return append(e, b...)
}

func edatetime(name string, millis int64) []byte {
	e := []byte{bsonDatetime}
	e = append(e, cstr(name)...)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(millis))
	return append(e, b...)
}

func eobjectid(name string, id [12]byte) []byte {
	e := []byte{bsonObjectID}
	e = append(e, cstr(name)...)
	return append(e, id[:]...)
}

// TestResult_ScalarTypesRoutedThroughMaskingWithTypeKind is the regression test for
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B Mongo extension: bool/int64/datetime/objectId
// leaves must reach the masker with FreeText=false and the mapped TypeKind (never FreeText=true,
// which would let a content detector run against raw binary bytes and almost certainly corrupt or
// garble them) — before this fix these types never reached the masker at all.
func TestResult_ScalarTypesRoutedThroughMaskingWithTypeKind(t *testing.T) {
	doc := bdoc(
		ebool("is_active", true),
		eint64("balance", 4200),
		edatetime("dob", 631152000000),
		eobjectid("ref", [12]byte{1, 2, 3}),
		estring("name", "Alice"), // control: still routed as FreeText=true, unaffected by Gap B
	)
	cm := &colCapturingMasker{}
	bm := &bsonMasker{ctx: context.Background(), masker: cm}
	if _, err := bm.result(doc, ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]struct {
		freeText bool
		kind     mask.TypeKind
	}{
		"is_active": {false, mask.TypeKindBool},
		"balance":   {false, mask.TypeKindNumeric},
		"dob":       {false, mask.TypeKindDate},
		"ref":       {false, mask.TypeKindObjectID},
		"name":      {true, mask.TypeKindUnspecified},
	}
	seen := map[string]bool{}
	for _, cols := range cm.calls {
		for _, c := range cols {
			w, ok := want[c.Name]
			if !ok {
				continue
			}
			seen[c.Name] = true
			if c.FreeText != w.freeText || c.TypeKind != w.kind {
				t.Errorf("col %q: FreeText=%v TypeKind=%v, want FreeText=%v TypeKind=%v", c.Name, c.FreeText, c.TypeKind, w.freeText, w.kind)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("expected column %q to reach the masker, but it never did", name)
		}
	}
}

// TestResult_UnmappedScalarTypesPassThrough confirms the deliberate exclusions in bsonTypeKind
// (Timestamp, MinKey/MaxKey, Null/Undefined) still bypass masking entirely, exactly as before Gap
// B's Mongo support existed — no mask.Column is ever built for them.
func TestResult_UnmappedScalarTypesPassThrough(t *testing.T) {
	nullElem := append([]byte{bsonNull}, cstr("deleted_at")...)
	doc := bdoc(nullElem)
	cm := &colCapturingMasker{}
	bm := &bsonMasker{ctx: context.Background(), masker: cm}
	out, err := bm.result(doc, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cm.calls) != 0 {
		t.Fatalf("expected bsonNull to never reach the masker, got %d calls", len(cm.calls))
	}
	if string(out) != string(doc) {
		t.Fatal("expected the document to pass through byte-identical")
	}
}

// TestPathOverlay_RedactsBSONDatetimeWithConfirmedLabel is the end-to-end regression test: a
// confirmed label on a BSON datetime field must substitute a real, fixed-width zero-valued
// datetime (all-zero 8 bytes = epoch), not the literal string PathOverlay's typeValidPlaceholder
// table returns and not the raw value left untouched.
func TestPathOverlay_RedactsBSONDatetimeWithConfirmedLabel(t *testing.T) {
	store := label.NewMemStore()
	ctx := context.Background()
	_ = store.Put(ctx, label.Label{
		ObjectID: "org1:mongo:app:users", FieldPath: "dob", Source: label.SourceManual, Profile: "full_redact",
	})
	overlay := mask.NewPathOverlay(store)

	doc := bdoc(edatetime("dob", 631152000000))
	bm := &bsonMasker{ctx: ctx, masker: overlay, orgID: "org1", curObjectID: "org1:mongo:app:users"}
	out, err := bm.result(doc, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Re-parse the masked document and confirm the datetime field is now all-zero (epoch), not the
	// original 631152000000ms value, and still exactly 8 bytes (BSON's fixed datetime width).
	var gotMillis int64
	var found bool
	_, _ = rewriteDoc(out, func(typ byte, name string, value []byte) ([]byte, error) {
		if name == "dob" {
			found = true
			if typ != bsonDatetime {
				t.Fatalf("expected the field to remain typed as bsonDatetime, got type 0x%02x", typ)
			}
			if len(value) != 8 {
				t.Fatalf("expected 8 bytes for a datetime placeholder, got %d", len(value))
			}
			gotMillis = int64(binary.LittleEndian.Uint64(value))
		}
		return value, nil
	})
	if !found {
		t.Fatal("dob field missing from the masked document")
	}
	if gotMillis != 0 {
		t.Fatalf("expected a zero-valued datetime placeholder, got %d", gotMillis)
	}
}

// TestPathOverlay_TypedBSONFieldWithoutConfirmedLabelUntouched confirms an unlabelled scalar field
// still passes through unchanged, even though it now reaches the masker (unlike before Gap B) — a
// miss must never corrupt the value, matching every other masker's fallthrough contract.
func TestPathOverlay_TypedBSONFieldWithoutConfirmedLabelUntouched(t *testing.T) {
	store := label.NewMemStore()
	overlay := mask.NewPathOverlay(store)
	doc := bdoc(eint64("balance", 4200))
	bm := &bsonMasker{ctx: context.Background(), masker: overlay, orgID: "org1", curObjectID: "org1:mongo:app:accounts"}
	out, err := bm.result(doc, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != string(doc) {
		t.Fatal("expected an unlabelled scalar field to pass through byte-identical")
	}
}
