package mysql

import (
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
)

// FuzzColumnIdentity guards the "never corrupt, fall through" contract for the densest hand-rolled
// offset arithmetic in this package: a malformed or truncated COLUMN_DEFINITION41 packet from the
// upstream MySQL server (or a protocol desync following a parsing bug elsewhere) must degrade to
// empty strings, never panic.
func FuzzColumnIdentity(f *testing.F) {
	f.Add(colDef("email"))
	f.Add(colDefAliased("contact_info", "email", 0xFD))
	f.Add(colDefTyped("id", 0x03))
	f.Add([]byte{})
	f.Add([]byte{0xFB})          // lenenc NULL marker with nothing after it
	f.Add([]byte{0xFE, 1, 2, 3}) // lenenc 8-byte-length marker with a truncated length field
	f.Fuzz(func(t *testing.T, p []byte) {
		_, _, _, _, _ = columnIdentity(p)
	})
}

// FuzzMaskTextRow guards the text-protocol row decoder every query result row passes through: a
// malformed/adversarial row payload (or a legitimate row following a protocol desync elsewhere)
// must degrade to ok=false, never panic or corrupt bytes.
func FuzzMaskTextRow(f *testing.F) {
	row := appendLenEncInt(nil, 1)
	row = append(row, '7')
	f.Add(row)
	f.Add([]byte{0xFB})
	f.Add([]byte{})
	f.Add([]byte{0xFE, '0', '0', '0', '0', '0', '0', '0', 0xF3})
	f.Fuzz(func(t *testing.T, payload []byte) {
		_, _, _, _ = maskTextRow(context.Background(), payload, nil, mask.Noop{})
	})
}
