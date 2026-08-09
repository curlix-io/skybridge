package postgres

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// rowDescription builds a 'T' message payload for the given text-format column names, all typed
// as the untyped/unknown OID (0) — i.e. free-text-eligible, matching prior test behavior.
func rowDescriptionPayload(names ...string) []byte {
	oids := make([]uint32, len(names))
	return rowDescriptionPayloadTyped(names, oids)
}

// rowDescriptionPayloadTyped is rowDescriptionPayload plus an explicit Postgres type OID per
// column, for exercising nonFreeTextTypeOIDs handling (e.g. 1184 = timestamptz).
func rowDescriptionPayloadTyped(names []string, oids []uint32) []byte {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(names)))
	buf.Write(u16[:])
	for i, n := range names {
		buf.WriteString(n)
		buf.WriteByte(0)
		buf.Write(make([]byte, 6)) // tableOID(4) colAttr(2)
		var oidBytes [4]byte
		binary.BigEndian.PutUint32(oidBytes[:], oids[i])
		buf.Write(oidBytes[:])
		buf.Write(make([]byte, 6)) // typeSize(2) typeMod(4)
		buf.Write([]byte{0, 0})    // formatCode 0 = text
	}
	return buf.Bytes()
}

// dataRowPayload builds a 'D' message payload; a nil value encodes SQL NULL.
func dataRowPayload(vals ...[]byte) []byte {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(vals)))
	buf.Write(u16[:])
	var u32 [4]byte
	for _, v := range vals {
		if v == nil {
			binary.BigEndian.PutUint32(u32[:], 0xFFFFFFFF)
			buf.Write(u32[:])
			continue
		}
		binary.BigEndian.PutUint32(u32[:], uint32(len(v)))
		buf.Write(u32[:])
		buf.Write(v)
	}
	return buf.Bytes()
}

func TestParseRowDescription(t *testing.T) {
	cols := parseRowDescription(rowDescriptionPayload("id", "email", "name"))
	if len(cols) != 3 {
		t.Fatalf("want 3 cols, got %d", len(cols))
	}
	if cols[1].Name != "email" || !cols[1].Text {
		t.Fatalf("unexpected col: %+v", cols[1])
	}
	if !cols[1].FreeText {
		t.Fatalf("untyped/unknown-OID column should default free-text eligible: %+v", cols[1])
	}
}

// TestParseRowDescriptionExcludesTypedColumnsFromFreeText is the regression test for the actual
// production bug this typeOID plumbing fixes: Presidio's DATE_TIME recognizer confidently flags an
// ordinary timestamptz value (e.g. "2024-07-05 00:13:50.654762+00:00") as PII and redacts it, but a
// client type-decoding that column (psycopg2 et al.) then fails with "unable to parse date" trying
// to parse the redaction placeholder as a timestamp — corrupting the response, not just
// over-masking. A typed column must never be marked FreeText so no detector ever runs against it.
func TestParseRowDescriptionExcludesTypedColumnsFromFreeText(t *testing.T) {
	names := []string{"id", "created_at", "note", "amount", "is_active"}
	oids := []uint32{23, 1184, 25, 1700, 16} // int4, timestamptz, text, numeric, bool
	cols := parseRowDescription(rowDescriptionPayloadTyped(names, oids))
	if len(cols) != 5 {
		t.Fatalf("want 5 cols, got %d", len(cols))
	}
	want := map[string]bool{
		"id":         false,
		"created_at": false,
		"note":       true,
		"amount":     false,
		"is_active":  false,
	}
	for _, c := range cols {
		if c.FreeText != want[c.Name] {
			t.Errorf("col %q: FreeText=%v, want %v", c.Name, c.FreeText, want[c.Name])
		}
	}
}

// TestParseRowDescriptionExcludesCatalogNameType is the regression test for a second, related
// production bug found via the same session: Postgres's Studio schema explorer (list
// tables/columns/functions) queries system catalogs — pg_class.relname, pg_namespace.nspname,
// pg_proc.proname, etc., all typed OID 19 ("name") — over this same masked connection. A table
// name is structural metadata, never user data; without this exclusion Presidio's NRP (nationality/
// religious/political) recognizer confidently misclassified the real table name
// "access_request_rules" as PII and redacted it to "[redacted]" in the explorer sidebar itself.
func TestParseRowDescriptionExcludesCatalogNameType(t *testing.T) {
	names := []string{"relname", "nspname"}
	oids := []uint32{19, 19} // Postgres "name" type
	cols := parseRowDescription(rowDescriptionPayloadTyped(names, oids))
	for _, c := range cols {
		if c.FreeText {
			t.Errorf("col %q (Postgres name type): FreeText=true, want false", c.Name)
		}
	}
}

// TestMaskDataRowNeverRedactsTypedTimestampColumn exercises the full pipeline (RowDescription ->
// DataRow) with a masker that mimics Presidio's real DATE_TIME false positive, confirming the
// typed column is protected end-to-end, not just at the parseRowDescription layer.
func TestMaskDataRowNeverRedactsTypedTimestampColumn(t *testing.T) {
	names := []string{"created_at", "note"}
	oids := []uint32{1184, 25} // timestamptz, text
	cols := parseRowDescription(rowDescriptionPayloadTyped(names, oids))

	dateTimeLikeValue := []byte("2024-07-05 00:13:50.654762+00:00")
	payload := dataRowPayload(dateTimeLikeValue, []byte("2024-07-05 is my note"))
	// dateTimeGuessingMasker redacts ANY free-text value that looks date-shaped, mimicking
	// Presidio's DATE_TIME recognizer's real-world false-positive behavior on ordinary timestamps.
	masker := dateTimeGuessingMasker{}

	out, values, err := maskDataRow(context.Background(), payload, cols, masker)
	if err != nil {
		t.Fatal(err)
	}
	_ = out
	if string(values[0]) != string(dateTimeLikeValue) {
		t.Fatalf("typed timestamptz column must never be redacted, got %q", values[0])
	}
	if string(values[1]) == "2024-07-05 is my note" {
		t.Fatal("free-text column should have been redacted by the detector in this test")
	}
}

// dateTimeGuessingMasker redacts any free-text column value containing a date-shaped substring —
// standing in for Presidio's real DATE_TIME recognizer without a network call in this test.
type dateTimeGuessingMasker struct{}

func (dateTimeGuessingMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	for i := range row {
		if row[i] == nil || i >= len(cols) || !cols[i].Text || !cols[i].FreeText {
			continue
		}
		if strings.Contains(string(row[i]), "2024-07-05") {
			row[i] = []byte("<DATE_TIME>")
		}
	}
	return row, nil
}

// columnMasker redacts any field whose column name is in the set.
type columnMasker struct{ redact map[string]bool }

func (c columnMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	for i := range row {
		if row[i] == nil {
			continue
		}
		if i < len(cols) && c.redact[strings.ToLower(cols[i].Name)] {
			row[i] = []byte("***")
		}
	}
	return row, nil
}

func TestMaskDataRowRedactsNamedColumn(t *testing.T) {
	cols := parseRowDescription(rowDescriptionPayload("id", "email"))
	payload := dataRowPayload([]byte("7"), []byte("a@b.com"))
	masker := columnMasker{redact: map[string]bool{"email": true}}

	out, _, err := maskDataRow(context.Background(), payload, cols, masker)
	if err != nil {
		t.Fatal(err)
	}
	// Decode and check: id unchanged, email redacted.
	n := int(binary.BigEndian.Uint16(out[0:2]))
	if n != 2 {
		t.Fatalf("want 2 fields, got %d", n)
	}
	off := 2
	get := func() []byte {
		l := int32(binary.BigEndian.Uint32(out[off : off+4]))
		off += 4
		if l < 0 {
			return nil
		}
		v := out[off : off+int(l)]
		off += int(l)
		return v
	}
	if string(get()) != "7" {
		t.Fatal("id should be unchanged")
	}
	if string(get()) != "***" {
		t.Fatal("email should be redacted")
	}
}

func TestMaskDataRowPreservesNull(t *testing.T) {
	cols := parseRowDescription(rowDescriptionPayload("id", "email"))
	payload := dataRowPayload([]byte("7"), nil)
	out, _, err := maskDataRow(context.Background(), payload, cols, mask.Noop{})
	if err != nil {
		t.Fatal(err)
	}
	off := 2 + 4 + 1 // count + id len + "7"
	flen := int32(binary.BigEndian.Uint32(out[off : off+4]))
	if flen != -1 {
		t.Fatalf("null should round-trip as -1, got %d", flen)
	}
}

// TestPipeBackendMasksStream feeds T, D, D, Z and asserts DataRows are masked and other messages
// pass through untouched.
func TestPipeBackendMasksStream(t *testing.T) {
	server := new(bytes.Buffer)
	writeRaw := func(typ byte, payload []byte) {
		var hdr [5]byte
		hdr[0] = typ
		binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
		server.Write(hdr[:])
		server.Write(payload)
	}
	writeRaw('T', rowDescriptionPayload("id", "email"))
	writeRaw('D', dataRowPayload([]byte("1"), []byte("alice@x.com")))
	writeRaw('D', dataRowPayload([]byte("2"), []byte("bob@x.com")))
	writeRaw('Z', []byte{'I'}) // ReadyForQuery (idle)

	client := new(bytes.Buffer)
	masker := columnMasker{redact: map[string]bool{"email": true}}
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), client, masker, wire.NoopRecorder{})
	if err == nil || err.Error() != "EOF" {
		t.Fatalf("expected EOF at stream end, got %v", err)
	}

	// The client stream must contain redacted emails and no plaintext addresses.
	out := client.Bytes()
	if bytes.Contains(out, []byte("alice@x.com")) || bytes.Contains(out, []byte("bob@x.com")) {
		t.Fatal("plaintext email leaked through the proxy")
	}
	if !bytes.Contains(out, []byte("***")) {
		t.Fatal("expected redaction token in output")
	}
	// Sanity: output should still parse as a sequence of typed messages ending in 'Z'.
	br := bufio.NewReader(bytes.NewReader(out))
	var last byte
	hdr := make([]byte, 5)
	for {
		if _, e := readFull(br, hdr); e != nil {
			break
		}
		last = hdr[0]
		l := binary.BigEndian.Uint32(hdr[1:5])
		skip := make([]byte, int(l)-4)
		if _, e := readFull(br, skip); e != nil {
			break
		}
	}
	if last != 'Z' {
		t.Fatalf("stream should end with ReadyForQuery, last=%c", last)
	}
}

// errMasker always fails, simulating a masking-service outage under strict mode.
type errMasker struct{}

func (errMasker) MaskRow(context.Context, []mask.Column, [][]byte) ([][]byte, error) {
	return nil, mask.ErrMaskerUnavailable
}

func TestPipeBackendAbortsOnMaskerFailure(t *testing.T) {
	server := new(bytes.Buffer)
	writeRaw := func(typ byte, payload []byte) {
		var hdr [5]byte
		hdr[0] = typ
		binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
		server.Write(hdr[:])
		server.Write(payload)
	}
	writeRaw('T', rowDescriptionPayload("id", "email"))
	writeRaw('D', dataRowPayload([]byte("1"), []byte("alice@x.com")))
	writeRaw('Z', []byte{'I'})

	client := new(bytes.Buffer)
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), client, errMasker{}, wire.NoopRecorder{})
	if !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
	if bytes.Contains(client.Bytes(), []byte("alice@x.com")) {
		t.Fatal("unmasked email must never reach the client when the masker fails in strict mode")
	}
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
