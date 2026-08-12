package postgres

import (
	"bufio"
	"bytes"
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
)

// FuzzParseRowDescription guards the "never corrupt, fall through" contract for the first parser
// every query result passes through: a malformed or adversarial RowDescription ('T' message) body
// from the upstream database must never panic, only ever return a best-effort (possibly empty)
// column list.
func FuzzParseRowDescription(f *testing.F) {
	noopResolver := func(context.Context, uint32, int16) (string, string) { return "", "" }
	f.Add(rowDescriptionPayload("id"))
	f.Add(rowDescriptionPayload("id", "email"))
	f.Add(rowDescriptionPayloadFull([]string{"id"}, []uint32{12345}, []int16{1}, []uint32{23}))
	f.Add([]byte{})
	f.Add([]byte{0, 1})
	f.Fuzz(func(t *testing.T, p []byte) {
		_ = parseRowDescription(context.Background(), p, noopResolver)
	})
}

// FuzzMaskDataRow guards the same contract for DataRow ('D' message) bodies. cols intentionally
// varies independently of the fuzzed payload's own field count — a real upstream could send a
// DataRow whose field count disagrees with the RowDescription that preceded it (protocol
// desync/bug), and that must degrade to an error, never a panic or corrupted bytes.
func FuzzMaskDataRow(f *testing.F) {
	cols := []mask.Column{{Name: "id"}, {Name: "email"}}
	f.Add(dataRowPayload([]byte("1"), []byte("a@b.com")), true)
	f.Add(dataRowPayload([]byte("1")), true)
	f.Add(dataRowPayload(nil, nil), true)
	f.Add([]byte{}, false)
	f.Add([]byte{0, 2}, false)
	f.Fuzz(func(t *testing.T, p []byte, withCols bool) {
		useCols := cols
		if !withCols {
			useCols = nil
		}
		_, _, _ = maskDataRow(context.Background(), p, useCols, mask.Noop{})
	})
}

// FuzzReadBackendMessage guards the length-prefixed message reader every backend reply passes
// through: readBackendMessage must reject an oversized or truncated length prefix rather than
// attempting to allocate/read past what's actually available.
func FuzzReadBackendMessage(f *testing.F) {
	f.Add([]byte{'Z', 0, 0, 0, 4})
	f.Add(append([]byte{'D'}, dataRowPayload([]byte("x"))...))
	f.Add([]byte{})
	f.Add([]byte{'T', 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		br := bufio.NewReader(bytes.NewReader(raw))
		_, _, _ = readBackendMessage(br)
	})
}
