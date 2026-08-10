package postgres

import "strings"

// The functions below are thin test-only shims over the parsing logic that used to live inline in
// this package (before it was extracted to internal/wire/scram): auth_test.go/gap_test.go's fake
// SCRAM server harnesses parse the client's own SCRAM messages to build valid server responses,
// which is fixture logic, not something scramClientExchange itself needs anymore now that it
// delegates to scram.ClientConversation. Kept minimal and local to avoid exporting parsing
// internals from the scram package just for test fixtures.

func parseSCRAMAttrsForTest(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func mechanismOfferedForTest(payload []byte, mech string) bool {
	for _, m := range strings.Split(string(payload), "\x00") {
		if m == mech {
			return true
		}
	}
	return false
}
