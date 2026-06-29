package mysql

import (
	"bufio"
	"bytes"
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
)

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

// colDef builds a minimal PROTOCOL_41 column-definition payload with the given column name.
func colDef(name string) []byte {
	var p []byte
	lenStr := func(s string) {
		p = appendLenEncInt(p, uint64(len(s)))
		p = append(p, s...)
	}
	lenStr("def")                         // catalog
	lenStr("test")                        // schema
	lenStr("t")                           // table
	lenStr("t")                           // org_table
	lenStr(name)                          // name
	lenStr(name)                          // org_name
	p = append(p, 0x0c)                   // length of fixed-length fields
	p = append(p, 0x21, 0x00)             // charset
	p = append(p, 0x00, 0x01, 0x00, 0x00) // column length
	p = append(p, 0xFD)                   // type (VAR_STRING)
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

func TestMaskTextRow(t *testing.T) {
	cols := []mask.Column{{Name: "id", Text: true}, {Name: "email", Text: true}}
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})

	// row: id="7", email="alice@example.com"
	var row []byte
	row = appendLenEncInt(row, 1)
	row = append(row, '7')
	row = appendLenEncInt(row, uint64(len("alice@example.com")))
	row = append(row, "alice@example.com"...)

	out, ok := maskTextRow(context.Background(), row, cols, overlay)
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

func TestMaskTextRowPreservesNull(t *testing.T) {
	cols := []mask.Column{{Name: "email", Text: true}}
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	row := []byte{0xFB} // single NULL
	out, ok := maskTextRow(context.Background(), row, cols, overlay)
	if !ok || len(out) != 1 || out[0] != 0xFB {
		t.Fatalf("NULL not preserved: out=%v ok=%v", out, ok)
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
	_ = s.serverToClient(context.Background(), sb, &out, overlay)

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

// TestServerToClientForwardsNonQuery verifies that without a pending query, packets pass through
// untouched (e.g. handshake/auth/OK traffic).
func TestServerToClientForwardsNonQuery(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	okPayload := []byte{pktOK, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	in := pkt(1, okPayload)

	var out bytes.Buffer
	sb := bufio.NewReader(bytes.NewReader(in))
	_ = s.serverToClient(context.Background(), sb, &out, mask.Noop{})

	if !bytes.Equal(out.Bytes(), in) {
		t.Fatalf("non-query traffic altered: got %v want %v", out.Bytes(), in)
	}
}
