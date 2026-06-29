package postgres

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
)

// rowDescription builds a 'T' message payload for the given text-format column names.
func rowDescriptionPayload(names ...string) []byte {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(names)))
	buf.Write(u16[:])
	for _, n := range names {
		buf.WriteString(n)
		buf.WriteByte(0)
		// tableOID(4) colAttr(2) typeOID(4) typeSize(2) typeMod(4) formatCode(2)
		buf.Write(make([]byte, 16))
		buf.Write([]byte{0, 0}) // formatCode 0 = text
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

	out, err := maskDataRow(context.Background(), payload, cols, masker)
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
	out, err := maskDataRow(context.Background(), payload, cols, mask.Noop{})
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
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), client, masker)
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
