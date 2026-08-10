// Upstream-auth origination for Mongo credential injection — the counterpart to clientauth.go.
// authenticateUpstream sends a fresh hello + saslStart/saslContinue conversation to the real
// MongoDB server using the credential the control plane resolved, so the real credential is never
// exposed to the client (which only ever holds an opaque, one-time session token — see
// clientauth.go's package doc).
package mongo

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/curlix-io/skybridge/internal/wire"
	"github.com/curlix-io/skybridge/internal/wire/scram"
)

// mechanismUnavailableCode is MongoDB's error code for "saslStart named a mechanism this user has
// no credentials for" (errmsg contains "MechanismUnavailable"), returned synchronously in the
// saslStart command reply itself (ok:0) — distinct from a bad-password failure, which instead
// completes the full exchange and fails verification at the end. Used to decide the SHA-256 ->
// SHA-1 fallback without guessing from errmsg text alone.
const mechanismUnavailableCode = 334

// authenticateUpstream originates a fresh Mongo connection auth against the upstream using cred,
// preferring SCRAM-SHA-256 and falling back to SCRAM-SHA-1 only when the upstream reports
// MechanismUnavailable for SHA-256 (MongoDB <4.0 or a user provisioned with SHA-1-only
// credentials) — see package doc and the design notes in docs/design/skybridge-masking-
// architecture.md for why both are supported. cred.Database (when set) is the authSource;
// otherwise defaults to "admin", matching typical MongoDB deployments.
func authenticateUpstream(upstream *bufio.ReadWriter, cred wire.UpstreamCredential) error {
	authDB := cred.Database
	if authDB == "" {
		authDB = "admin"
	}
	err := scramExchange(upstream, scram.SHA256, cred.Username, cred.Password, authDB)
	if err == nil {
		return nil
	}
	var mu *mechanismUnavailableError
	if !errors.As(err, &mu) {
		return err
	}
	return scramExchange(upstream, scram.SHA1, cred.Username, cred.Password, authDB)
}

// mechanismUnavailableError marks a saslStart failure specifically attributable to the requested
// mechanism not being available for this user (MongoDB error code 334), so authenticateUpstream
// can distinguish "try SHA-1 instead" from "this password is wrong" or a transport error.
type mechanismUnavailableError struct{ err error }

func (e *mechanismUnavailableError) Error() string { return e.err.Error() }
func (e *mechanismUnavailableError) Unwrap() error { return e.err }

// scramExchange runs one full SCRAM conversation (saslStart + one saslContinue) for mechanism
// against the upstream, using the shared internal/wire/scram client-conversation math under
// Mongo's BSON/OP_MSG framing.
func scramExchange(upstream *bufio.ReadWriter, mechanism, username, password, authDB string) error {
	conv, err := scram.NewClientConversation(mechanism, username, password)
	if err != nil {
		return err
	}
	clientFirst := conv.ClientFirstMessage()

	startBody := newDoc().
		addInt32("saslStart", 1).
		addString("mechanism", mechanism).
		addBinary("payload", []byte(clientFirst)).
		addString("$db", authDB).
		bytes()
	requestID := int32(1)
	if err := writeAndFlush(upstream, opMsgRequestMessage(startBody, requestID)); err != nil {
		return err
	}
	startReplyMsg, err := readMessage(upstream.Reader)
	if err != nil {
		return err
	}
	startReply, ok := parseCommandDocGeneric(startReplyMsg)
	if !ok {
		return fmt.Errorf("mongo: could not parse upstream saslStart reply")
	}
	if isNotOK(startReply) {
		if code, hasCode := int32Field(startReply, "code"); hasCode && code == mechanismUnavailableCode {
			return &mechanismUnavailableError{err: fmt.Errorf("mongo upstream: %s not available for this user", mechanism)}
		}
		return fmt.Errorf("mongo upstream rejected saslStart: %s", errmsgField(startReply))
	}
	conversationID, _ := int32Field(startReply, "conversationId")
	serverFirst := string(binaryField(startReply, "payload"))

	clientFinal, err := conv.Step2(serverFirst)
	if err != nil {
		return fmt.Errorf("mongo: %w", err)
	}

	continueBody := newDoc().
		addInt32("saslContinue", 1).
		addInt32("conversationId", conversationID).
		addBinary("payload", []byte(clientFinal)).
		addString("$db", authDB).
		bytes()
	requestID++
	if err := writeAndFlush(upstream, opMsgRequestMessage(continueBody, requestID)); err != nil {
		return err
	}
	continueReplyMsg, err := readMessage(upstream.Reader)
	if err != nil {
		return err
	}
	continueReply, ok := parseCommandDocGeneric(continueReplyMsg)
	if !ok {
		return fmt.Errorf("mongo: could not parse upstream saslContinue reply")
	}
	if isNotOK(continueReply) {
		return fmt.Errorf("mongo upstream rejected saslContinue: %s", errmsgField(continueReply))
	}
	serverFinal := string(binaryField(continueReply, "payload"))
	if err := conv.Step3(serverFinal); err != nil {
		return fmt.Errorf("mongo: %w", err)
	}
	// MongoDB's SCRAM does not require a trailing empty saslContinue once done:true is returned
	// (verified against the wire protocol spec) — the conversation is complete here.
	return nil
}

func writeAndFlush(rw *bufio.ReadWriter, msg []byte) error {
	if _, err := rw.Writer.Write(msg); err != nil {
		return err
	}
	return rw.Writer.Flush()
}

// isNotOK reports whether a command reply's "ok" field is 0 (BSON double or int32, per MongoDB's
// convention of accepting either encoding for this field).
func isNotOK(doc map[string]bsonElem) bool {
	e, has := doc["ok"]
	if !has {
		return true
	}
	switch e.typ {
	case bsonDouble:
		if len(e.value) < 8 {
			return true
		}
		return binary.LittleEndian.Uint64(e.value) == 0
	case bsonInt32:
		if len(e.value) < 4 {
			return true
		}
		return binary.LittleEndian.Uint32(e.value) == 0
	default:
		return true
	}
}

func int32Field(doc map[string]bsonElem, name string) (int32, bool) {
	e, ok := doc[name]
	if !ok || e.typ != bsonInt32 || len(e.value) < 4 {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(e.value)), true
}

func errmsgField(doc map[string]bsonElem) string {
	if s := stringField(doc, "errmsg"); s != "" {
		return s
	}
	return "unknown error"
}
