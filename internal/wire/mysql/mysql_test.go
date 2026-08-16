package mysql

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// errMasker always fails, simulating a masking-service outage under strict mode.
type errMasker struct{}

func (errMasker) MaskRow(context.Context, []mask.Column, [][]byte) ([][]byte, error) {
	return nil, mask.ErrMaskerUnavailable
}

func TestReadLenEncInt(t *testing.T) {
	cases := []struct {
		in   []byte
		val  uint64
		n    int
		ok   bool
		name string
	}{
		{[]byte{0x05}, 5, 1, true, "1-byte"},
		{[]byte{0xFC, 0x10, 0x01}, 0x0110, 3, true, "2-byte"},
		{[]byte{0xFD, 0x01, 0x00, 0x01}, 0x010001, 4, true, "3-byte"},
		{[]byte{0xFE, 1, 0, 0, 0, 0, 0, 0, 0}, 1, 9, true, "8-byte"},
		{[]byte{0xFC, 0x01}, 0, 0, false, "truncated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, n, ok := readLenEncInt(c.in, 0)
			if v != c.val || n != c.n || ok != c.ok {
				t.Fatalf("got (%d,%d,%v) want (%d,%d,%v)", v, n, ok, c.val, c.n, c.ok)
			}
		})
	}
}

func TestAppendLenEncIntRoundTrip(t *testing.T) {
	for _, v := range []uint64{0, 1, 250, 251, 0xFFFF, 0x10000, 0xFFFFFF, 0x1000000} {
		got := appendLenEncInt(nil, v)
		back, _, ok := readLenEncInt(got, 0)
		if !ok || back != v {
			t.Fatalf("roundtrip v=%d: back=%d ok=%v", v, back, ok)
		}
	}
}

// colDef builds a minimal PROTOCOL_41 column-definition payload with the given column name and
// wire type (default VAR_STRING when 0x00 is passed — use colDefTyped for other types).
func colDef(name string) []byte {
	return colDefTyped(name, 0xFD) // VAR_STRING
}

// colDefTyped is colDef plus an explicit MySQL column wire type (see nonFreeTextColumnTypes).
func colDefTyped(name string, colType byte) []byte {
	return colDefAliased(name, name, colType)
}

// colDefAliased is colDefTyped but with name (the aliased display name) and orgName (the real,
// unaliased column name) set independently — see TestColumnIdentityResolvesRealNameForAliasedColumn.
func colDefAliased(name, orgName string, colType byte) []byte {
	var p []byte
	lenStr := func(s string) {
		p = appendLenEncInt(p, uint64(len(s)))
		p = append(p, s...)
	}
	lenStr("def")                         // catalog
	lenStr("test")                        // schema
	lenStr("t")                           // table
	lenStr("t")                           // org_table
	lenStr(name)                          // name (aliased display name)
	lenStr(orgName)                       // org_name (real, unaliased column name)
	p = append(p, 0x0c)                   // length of fixed-length fields
	p = append(p, 0x21, 0x00)             // charset
	p = append(p, 0x00, 0x01, 0x00, 0x00) // column length
	p = append(p, colType)                // type
	p = append(p, 0x00, 0x00)             // flags
	p = append(p, 0x00)                   // decimals
	p = append(p, 0x00, 0x00)             // filler
	return p
}

func TestColumnName(t *testing.T) {
	if got := columnName(colDef("email")); got != "email" {
		t.Fatalf("columnName = %q want email", got)
	}
}

func TestColumnIdentity(t *testing.T) {
	name, schema, orgTable, orgName, freeText := columnIdentity(colDef("email"))
	if name != "email" || schema != "test" || orgTable != "t" || orgName != "email" {
		t.Fatalf("columnIdentity = (%q,%q,%q,%q) want (email,test,t,email)", name, schema, orgTable, orgName)
	}
	if !freeText {
		t.Fatal("VAR_STRING column should be free-text eligible")
	}
}

// TestLenEncStrSpanRejectsOverflowingLength is the regression test for a fuzz-found panic: a lenenc
// length field near uint64's max (from a truncated/corrupted 8-byte length marker, 0xFE) converts to
// a negative int on overflow, which used to slip past the off+total>len(p) bounds check (a negative
// total always satisfies "not greater than") and let the caller advance its offset out of bounds,
// panicking on the next slice read. lenEncStrSpan must reject any length claim above len(p) instead.
func TestLenEncStrSpanRejectsOverflowingLength(t *testing.T) {
	p := []byte{0xFE, '0', '0', '0', '0', '0', '0', '0', 0xF3}
	if _, ok := lenEncStrSpan(p, 0); ok {
		t.Fatal("expected lenEncStrSpan to reject a length far exceeding the buffer size")
	}
}

// TestColumnIdentityRejectsOverflowingLength is columnIdentity's end-to-end counterpart to
// TestLenEncStrSpanRejectsOverflowingLength — the same crafted input, driven through the full
// column-definition parser rather than the helper directly, must degrade to unresolved, not panic.
func TestColumnIdentityRejectsOverflowingLength(t *testing.T) {
	p := []byte{0xFE, '0', '0', '0', '0', '0', '0', '0', 0xF3}
	name, schema, orgTable, orgName, freeText := columnIdentity(p)
	if name != "" || schema != "" || orgTable != "" || orgName != "" || !freeText {
		t.Fatalf("columnIdentity = (%q,%q,%q,%q,%v), want all-empty and freeText=true (unresolved)", name, schema, orgTable, orgName, freeText)
	}
}

// TestColumnIdentityResolvesRealNameForAliasedColumn is the regression test for
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap A: a query aliasing a column (e.g. "SELECT email AS
// contact_info") must still let a path-scoped label confirmed on "email" match — orgName, not name,
// is what a caller should key a PathOverlay lookup on.
func TestColumnIdentityResolvesRealNameForAliasedColumn(t *testing.T) {
	name, _, _, orgName, _ := columnIdentity(colDefAliased("contact_info", "email", 0xFD))
	if name != "contact_info" {
		t.Fatalf("name = %q, want the aliased display name %q", name, "contact_info")
	}
	if orgName != "email" {
		t.Fatalf("orgName = %q, want the real column name %q", orgName, "email")
	}
}

// TestColumnIdentityExcludesTypedColumnsFromFreeText is the regression test for the same class of
// bug fixed in the Postgres engine (see postgres_test.go's
// TestParseRowDescriptionExcludesTypedColumnsFromFreeText): Presidio's DATE_TIME/numeric
// recognizers can confidently misclassify an ordinary DATETIME/DECIMAL/etc. value as PII and
// redact it, producing a value the client's type decoder can no longer parse. MySQL's
// column-definition packet carries the real wire type (unlike Postgres's separate mechanism, it's
// a single trailing byte) — columnIdentity must report freeText=false for it.
func TestColumnIdentityExcludesTypedColumnsFromFreeText(t *testing.T) {
	cases := []struct {
		name     string
		colType  byte
		freeText bool
	}{
		{"created_at", 0x0c, false}, // DATETIME
		{"amount", 0xf6, false},     // NEWDECIMAL
		{"is_active", 0x01, false},  // TINY (MySQL's bool)
		{"note", 0xfd, true},        // VAR_STRING
		{"description", 0xfc, true}, // BLOB (opaque, but historically treated as scannable text)
	}
	for _, c := range cases {
		_, _, _, _, freeText := columnIdentity(colDefTyped(c.name, c.colType))
		if freeText != c.freeText {
			t.Errorf("col %q type=0x%02x: freeText=%v, want %v", c.name, c.colType, freeText, c.freeText)
		}
	}
}

func TestState_ObjectID(t *testing.T) {
	s := &state{orgID: "org1"}
	if got := s.objectID("test", "t"); got != "org1:mysql:test:t" {
		t.Fatalf("objectID = %q", got)
	}
	if got := s.objectID("test", "t"); got == "" {
		t.Fatal("expected non-empty ObjectID when orgID and orgTable are set")
	}
	if (&state{}).objectID("test", "t") != "" {
		t.Fatal("expected empty ObjectID when orgID is unset")
	}
	if s.objectID("test", "") != "" {
		t.Fatal("expected empty ObjectID when orgTable is unset (e.g. a derived/computed column)")
	}
}

// TestLenEncStrRejectsOverflowingLength is lenEncStr's counterpart to
// TestLenEncStrSpanRejectsOverflowingLength: the same class of int-overflow-on-conversion bug, in
// the sibling helper that decodes a lenenc string's value rather than just its span.
func TestLenEncStrRejectsOverflowingLength(t *testing.T) {
	p := []byte{0xFE, '0', '0', '0', '0', '0', '0', '0', 0xF3}
	if got := lenEncStr(p, 0); got != "" {
		t.Fatalf("lenEncStr = %q, want empty for a length far exceeding the buffer size", got)
	}
}

// TestMaskTextRowRejectsOverflowingLength is the regression test for a fuzz-found panic in the
// text-protocol row decoder: a lenenc field length near uint64's max used to pass the
// off+int(l)>len(payload) bounds check after overflowing int on conversion (wrapping negative),
// then panic in make([]byte, l) with l still the original huge uint64. maskTextRow must instead
// signal ok=false (protocol-parse drift, safe by construction) so the caller forwards the packet
// unchanged rather than attempting to decode it.
func TestMaskTextRowRejectsOverflowingLength(t *testing.T) {
	row := []byte{0xFE, '0', '0', '0', '0', '0', '0', '0', 0xF3}
	_, _, ok, err := maskTextRow(context.Background(), row, nil, mask.Noop{}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for a length far exceeding the buffer size")
	}
}

func TestMaskTextRow(t *testing.T) {
	cols := []mask.Column{{Name: "id", Text: true, FreeText: true}, {Name: "email", Text: true, FreeText: true}}
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})

	// row: id="7", email="alice@example.com"
	var row []byte
	row = appendLenEncInt(row, 1)
	row = append(row, '7')
	row = appendLenEncInt(row, uint64(len("alice@example.com")))
	row = append(row, "alice@example.com"...)

	out, _, ok, err := maskTextRow(context.Background(), row, cols, overlay, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("maskTextRow returned ok=false")
	}
	if bytes.Contains(out, []byte("alice@example.com")) {
		t.Fatal("masked row still contains the email")
	}
	if !bytes.Contains(out, []byte("[redacted]")) {
		t.Fatal("masked row missing redaction token")
	}
	// id field must survive untouched.
	if !bytes.Contains(out, []byte{0x01, '7'}) {
		t.Fatal("id field corrupted")
	}
}

// fakeCollector records every Observe call, standing in for trafficsampler.Buffer.
type fakeCollector struct {
	observed map[string]string
}

func (c *fakeCollector) Observe(objectID, fieldPath, value string) {
	if c.observed == nil {
		c.observed = make(map[string]string)
	}
	c.observed[objectID+"|"+fieldPath] = value
}

// TestMaskTextRow_CollectsSamplesForFreeTextColumnsWithObjectID mirrors the equivalent postgres/
// dbquery tests: a free-text column carrying a resolved ObjectID observes its pre-mask value; a
// typed column and a column with no resolved ObjectID do not.
func TestMaskTextRow_CollectsSamplesForFreeTextColumnsWithObjectID(t *testing.T) {
	cols := []mask.Column{
		{Name: "note", Path: "note", ObjectID: "org1:mysql:app:users", Text: true, FreeText: true},
		{Name: "id", Path: "id", ObjectID: "org1:mysql:app:users", Text: true, FreeText: false},
		{Name: "other", Path: "other", ObjectID: "", Text: true, FreeText: true},
	}
	var row []byte
	row = appendLenEncInt(row, uint64(len("hello")))
	row = append(row, "hello"...)
	row = appendLenEncInt(row, 1)
	row = append(row, '7')
	row = appendLenEncInt(row, uint64(len("unscoped")))
	row = append(row, "unscoped"...)

	col := &fakeCollector{}
	_, _, ok, err := maskTextRow(context.Background(), row, cols, mask.Noop{}, col)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("maskTextRow returned ok=false")
	}
	if col.observed["org1:mysql:app:users|note"] != "hello" {
		t.Fatalf("expected a sample observed for the free-text column with a resolved ObjectID, got %v", col.observed)
	}
	if _, ok := col.observed["org1:mysql:app:users|id"]; ok {
		t.Fatal("expected no sample observed for a typed (non-free-text) column")
	}
	if _, ok := col.observed["|other"]; ok {
		t.Fatal("expected no sample observed for a column with no resolved ObjectID")
	}
}

func TestMaskTextRowPreservesNull(t *testing.T) {
	cols := []mask.Column{{Name: "email", Text: true, FreeText: true}}
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	row := []byte{0xFB} // single NULL
	out, _, ok, err := maskTextRow(context.Background(), row, cols, overlay, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || len(out) != 1 || out[0] != 0xFB {
		t.Fatalf("NULL not preserved: out=%v ok=%v", out, ok)
	}
}

func TestMaskTextRowPropagatesMaskerError(t *testing.T) {
	cols := []mask.Column{{Name: "email", Text: true, FreeText: true}}
	row := []byte{}
	row = appendLenEncInt(row, uint64(len("alice@example.com")))
	row = append(row, "alice@example.com"...)

	_, _, ok, err := maskTextRow(context.Background(), row, cols, errMasker{}, nil)
	if !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
	if ok {
		t.Fatal("ok must be false on masker error")
	}
}

func pkt(seq byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}, payload...)
}

func textRow(vals ...string) []byte {
	var p []byte
	for _, v := range vals {
		p = appendLenEncInt(p, uint64(len(v)))
		p = append(p, v...)
	}
	return p
}

func eofPacket() []byte {
	return []byte{pktEOF, 0x00, 0x00, 0x00, 0x00} // header, warnings=0, status=0
}

// TestServerToClientMasksResultSet drives a full text result set through the response side and
// asserts rows are masked while structure is preserved.
func TestServerToClientMasksResultSet(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	stream.Write(pkt(1, []byte{0x02}))    // column count = 2
	stream.Write(pkt(2, colDef("id")))    // col 1
	stream.Write(pkt(3, colDef("email"))) // col 2
	stream.Write(pkt(4, eofPacket()))     // end of columns (non-deprecate)
	stream.Write(pkt(5, textRow("1", "alice@example.com")))
	stream.Write(pkt(6, textRow("2", "bob@example.com")))
	stream.Write(pkt(7, eofPacket())) // terminator

	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	_ = s.serverToClient(context.Background(), sb, &out, overlay, wire.NoopRecorder{})

	got := out.Bytes()
	if bytes.Contains(got, []byte("alice@example.com")) || bytes.Contains(got, []byte("bob@example.com")) {
		t.Fatal("output still contains plaintext emails")
	}
	if bytes.Count(got, []byte("[redacted]")) != 2 {
		t.Fatalf("expected 2 redactions, got %d", bytes.Count(got, []byte("[redacted]")))
	}
	// Column metadata must be preserved verbatim.
	if !bytes.Contains(got, []byte("email")) {
		t.Fatal("column metadata lost")
	}
}

// TestServerToClientAbortsOnMaskerFailure asserts a masker error stops the result set mid-stream
// instead of forwarding the unmasked row to the client (strict-mode masking failure).
func TestServerToClientAbortsOnMaskerFailure(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	stream.Write(pkt(1, []byte{0x01}))
	stream.Write(pkt(2, colDef("email")))
	stream.Write(pkt(3, eofPacket()))
	stream.Write(pkt(4, textRow("alice@example.com")))
	stream.Write(pkt(5, eofPacket()))

	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	err := s.serverToClient(context.Background(), sb, &out, errMasker{}, wire.NoopRecorder{})
	if !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
	if bytes.Contains(out.Bytes(), []byte("alice@example.com")) {
		t.Fatal("unmasked email must never reach the client when the masker fails in strict mode")
	}
}

// TestServerToClientForwardsNonQuery verifies that without a pending query, packets pass through
// untouched (e.g. handshake/auth/OK traffic).
func TestServerToClientForwardsNonQuery(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	okPayload := []byte{pktOK, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	in := pkt(1, okPayload)

	var out bytes.Buffer
	sb := bufio.NewReader(bytes.NewReader(in))
	_ = s.serverToClient(context.Background(), sb, &out, mask.Noop{}, wire.NoopRecorder{})

	if !bytes.Equal(out.Bytes(), in) {
		t.Fatalf("non-query traffic altered: got %v want %v", out.Bytes(), in)
	}
}
