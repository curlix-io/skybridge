// Client-side auth termination for Mongo credential injection (mirrors postgres/auth.go's
// requestClientPassword and mysql/auth.go's AuthSwitchRequest-based mechanism-forcing trick).
//
// Unlike Postgres (which can request a cleartext password unconditionally) and MySQL (which can
// force a mechanism switch mid-handshake via AuthSwitchRequest), a MongoDB driver will not
// discover/select the PLAIN mechanism on its own — real MongoDB servers never advertise PLAIN via
// hello's saslSupportedMechs, so a driver only attempts PLAIN when the client is explicitly
// configured with authMechanism=PLAIN (e.g. in its connection string). This is a client-side setup
// requirement, not a protocol negotiation this proxy can force — analogous to MySQL credential
// injection already requiring the client to enable the mysql_clear_password plugin.
//
// Scope: OP_MSG only (modern mongosh/drivers), matching the masking engine's own scoping (it
// already only masks OP_MSG; legacy OP_REPLY/OP_QUERY are documented unmasked-passthrough
// limitations). A legacy OP_QUERY handshake returns a clear error rather than being parsed.
package mongo

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

const (
	opQuery = 2004 // legacy opcode; out of scope for injection, see package doc above

	saslMechanismPlain = "PLAIN"
)

// errLegacyHandshakeUnsupported is returned when the client's first message is not OP_MSG (e.g. a
// pre-3.6 driver's OP_QUERY isMaster) — credential injection requires a modern driver.
var errLegacyHandshakeUnsupported = errors.New("mongo: legacy OP_QUERY handshake is not supported for credential injection (use a modern driver/mongosh)")

// errPlainNotOffered is returned when the client's saslStart requests a mechanism other than
// PLAIN — the client must be configured with authMechanism=PLAIN to present its session token.
var errPlainNotOffered = fmt.Errorf("mongo: client did not request %s (configure authMechanism=%s to present the session token)", saslMechanismPlain, saslMechanismPlain)

// terminateClientAuth reads the client's hello and saslStart(PLAIN) commands, replies to hello
// normally (so the driver proceeds to auth) and returns the extracted secret (the PLAIN
// password, i.e. the opaque session token) and a startup map mirroring postgres/mysql's shape
// (at least "user" and "database"/authSource). It does NOT tell the client login succeeded —
// that happens only after the caller's upstream auth succeeds (see completeClientAuth below),
// mirroring postgres's deferred sendClientAuthOK pattern.
func terminateClientAuth(client *bufio.ReadWriter) (secret string, startup map[string]string, err error) {
	helloMsg, err := readMessage(client.Reader)
	if err != nil {
		return "", nil, err
	}
	if err := requireOpMsg(helloMsg); err != nil {
		return "", nil, err
	}
	helloDoc, ok := parseCommandDocGeneric(helloMsg)
	if !ok {
		return "", nil, errors.New("mongo: could not parse client hello/isMaster command")
	}
	// hello's own $db is the auth database (commonly "admin"), independent of whatever database
	// the client will eventually query — see package doc.
	authDB := stringField(helloDoc, "$db")
	if authDB == "" {
		authDB = "admin"
	}
	requestID := int32(binary.LittleEndian.Uint32(helloMsg[4:8]))
	if _, err := client.Writer.Write(helloReply(requestID)); err != nil {
		return "", nil, err
	}
	if err := client.Writer.Flush(); err != nil {
		return "", nil, err
	}

	saslMsg, err := readMessage(client.Reader)
	if err != nil {
		return "", nil, err
	}
	if err := requireOpMsg(saslMsg); err != nil {
		return "", nil, err
	}
	saslDoc, ok := parseCommandDocGeneric(saslMsg)
	if !ok {
		return "", nil, errors.New("mongo: could not parse client saslStart command")
	}
	if _, hasSaslStart := saslDoc["saslStart"]; !hasSaslStart {
		return "", nil, fmt.Errorf("mongo: expected saslStart, got a command with fields %v", fieldNames(saslDoc))
	}
	mechanism := stringField(saslDoc, "mechanism")
	if mechanism != saslMechanismPlain {
		return "", nil, errPlainNotOffered
	}
	payload := binaryField(saslDoc, "payload")
	authzid, authcid, password, err := decodePlainPayload(payload)
	if err != nil {
		return "", nil, fmt.Errorf("mongo: bad PLAIN payload: %w", err)
	}
	_ = authzid // RFC 4616 authzid is accepted but unused, matching typical PLAIN server behavior.

	saslDB := stringField(saslDoc, "$db")
	if saslDB == "" {
		saslDB = authDB
	}
	saslRequestID := int32(binary.LittleEndian.Uint32(saslMsg[4:8]))
	startup = map[string]string{"user": authcid, "database": saslDB}
	return password, startup, saslCompleteReplyAndFlush(client, saslRequestID)
}

// saslCompleteReplyAndFlush sends the PLAIN mechanism's single-round-trip completion reply
// ({ok:1, done:true, conversationId:1, payload:<empty>}) and flushes. PLAIN never needs a
// saslContinue, unlike SCRAM — see package doc.
func saslCompleteReplyAndFlush(client *bufio.ReadWriter, requestID int32) error {
	if _, err := client.Writer.Write(saslCompleteReply(requestID)); err != nil {
		return err
	}
	return client.Writer.Flush()
}

// requireOpMsg returns errLegacyHandshakeUnsupported for anything that isn't OP_MSG (in
// particular, legacy OP_QUERY isMaster handshakes) — see package doc's scoping.
func requireOpMsg(msg []byte) error {
	if len(msg) < headerLen {
		return errors.New("mongo: message too short to contain a header")
	}
	opcode := int32(binary.LittleEndian.Uint32(msg[12:16]))
	if opcode == opQuery {
		return errLegacyHandshakeUnsupported
	}
	if opcode != opMsg {
		return fmt.Errorf("mongo: expected OP_MSG, got opcode %d", opcode)
	}
	return nil
}

// decodePlainPayload decodes an RFC 4616 PLAIN payload: NUL authzid NUL authcid NUL password (the
// authzid segment is commonly empty, so the payload typically starts with a single NUL).
func decodePlainPayload(payload []byte) (authzid, authcid, password string, err error) {
	parts := strings.SplitN(string(payload), "\x00", 3)
	if len(parts) != 3 {
		return "", "", "", errors.New("expected 3 NUL-separated fields (authzid, authcid, password)")
	}
	return parts[0], parts[1], parts[2], nil
}
