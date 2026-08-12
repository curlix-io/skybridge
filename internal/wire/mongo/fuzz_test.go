package mongo

import "testing"

// FuzzRewriteDoc guards the "never corrupt, fall through" contract for the BSON document walker
// every client/server document passes through (directly, and recursively via body/cursor/batch
// resolution) — a malformed or adversarial document must degrade to an error, never a panic.
func FuzzRewriteDoc(f *testing.F) {
	f.Add(bdoc(estring("a", "b")))
	f.Add([]byte{1, 2})
	f.Add([]byte{})
	corrupted := bdoc(estring("a", "b"))
	corrupted[len(corrupted)-1] = 0xFF
	f.Add(corrupted)
	unterminated := []byte{bsonString}
	unterminated = append(unterminated, "find"...)
	f.Add(unterminated)
	f.Fuzz(func(t *testing.T, doc []byte) {
		_, _ = rewriteDoc(doc, func(byte, string, []byte) ([]byte, error) { return nil, nil })
	})
}

// FuzzParseCommandDoc guards the command-document parser used to correlate each request with the
// collection it targets for PathOverlay identity resolution — same contract as FuzzRewriteDoc.
func FuzzParseCommandDoc(f *testing.F) {
	f.Add(bdoc(estring("find", "orders")))
	f.Add([]byte{1, 2, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, doc []byte) {
		_, _ = parseCommandDoc(doc)
	})
}
