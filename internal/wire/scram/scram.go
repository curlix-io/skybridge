// Package scram implements the client role of SCRAM-SHA-1 and SCRAM-SHA-256 (RFC 5802), the
// message algebra only — no wire framing. Callers frame ClientFirstMessage/Step2's return
// value/Step3's input into their own protocol (Postgres's 'p'/'R' messages, Mongo's BSON
// saslStart/saslContinue commands, etc.).
//
// Extracted from internal/wire/postgres/auth.go's original inlined scramClientExchange (which
// mixed this math with Postgres message framing) so Mongo's upstream-auth origination can reuse
// the identical, already-tested SCRAM math under its own BSON framing. Postgres's auth.go was
// rewritten to call this package; its own tests are the regression gate for that extraction.
package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SCRAM-SHA-1 is a supported upstream mechanism (MongoDB <4.0), not used for anything else
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// Mechanism names, matching the SASL mechanism strings Postgres/MongoDB advertise on the wire.
const (
	SHA1   = "SCRAM-SHA-1"
	SHA256 = "SCRAM-SHA-256"
)

// ClientConversation drives one SCRAM client exchange against an upstream server. Not safe for
// concurrent use; a conversation is single-shot (one Step1/Step2/Step3 sequence per auth attempt).
type ClientConversation struct {
	mechanism   string
	newHash     func() hash.Hash
	authcName   string // value for the client-first-message "n=" field; "" for Postgres (username
	// already known via the startup packet), the real username for Mongo (required by the spec).
	password string

	clientNonce     string
	gs2Header       string
	clientFirstBare string

	// Set by Step2, needed by Step3.
	saltedPassword []byte
	authMessage    string
}

// NewClientConversation starts a SCRAM client conversation for mechanism (SHA1 or SHA256).
// authcName is the value to send in the client-first-message's "n=" field — pass "" when the
// upstream already knows the username through another channel (e.g. Postgres's StartupMessage),
// or the real username when the protocol requires it in-band (e.g. MongoDB).
func NewClientConversation(mechanism, authcName, password string) (*ClientConversation, error) {
	var newHash func() hash.Hash
	switch mechanism {
	case SHA1:
		newHash = sha1.New
	case SHA256:
		newHash = sha256.New
	default:
		return nil, fmt.Errorf("scram: unsupported mechanism %q (want %q or %q)", mechanism, SHA1, SHA256)
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	return &ClientConversation{
		mechanism: mechanism,
		newHash:   newHash,
		authcName: authcName,
		password:  password,

		clientNonce: nonce,
		gs2Header:   "n,,",
	}, nil
}

// ClientFirstMessage returns the client-first-message (gs2 header + bare message) to send as the
// SASL mechanism's initial response.
func (c *ClientConversation) ClientFirstMessage() string {
	c.clientFirstBare = "n=" + escapeSCRAMName(c.authcName) + ",r=" + c.clientNonce
	return c.gs2Header + c.clientFirstBare
}

// Step2 consumes the server-first-message and returns the client-final-message to send next.
func (c *ClientConversation) Step2(serverFirst string) (string, error) {
	attrs := parseAttrs(serverFirst)
	combinedNonce := attrs["r"]
	saltB64 := attrs["s"]
	iterStr := attrs["i"]
	if combinedNonce == "" || saltB64 == "" || iterStr == "" {
		return "", errors.New("scram: malformed server-first message")
	}
	if !strings.HasPrefix(combinedNonce, c.clientNonce) {
		return "", errors.New("scram: server nonce does not extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return "", fmt.Errorf("scram: bad salt: %w", err)
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 {
		return "", fmt.Errorf("scram: bad iteration count %q", iterStr)
	}

	c.saltedPassword = pbkdf2(c.newHash, []byte(saslPrep(c.password)), salt, iter, c.newHash().Size())
	clientKey := c.hmac(c.saltedPassword, "Client Key")
	storedKey := c.hash(clientKey)

	channelBinding := base64.StdEncoding.EncodeToString([]byte(c.gs2Header)) // "biws" for "n,,"
	clientFinalWithoutProof := "c=" + channelBinding + ",r=" + combinedNonce
	c.authMessage = c.clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	clientSignature := c.hmac(storedKey, c.authMessage)
	clientProof := make([]byte, len(clientKey))
	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}
	return clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof), nil
}

// Step3 verifies the server-final-message's signature ("v="), confirming the server actually
// knows the password (not just that it accepted our proof) — never treat auth as successful
// without calling this.
func (c *ClientConversation) Step3(serverFinal string) error {
	attrs := parseAttrs(serverFinal)
	gotSig, err := base64.StdEncoding.DecodeString(attrs["v"])
	if err != nil {
		return fmt.Errorf("scram: bad server signature: %w", err)
	}
	serverKey := c.hmac(c.saltedPassword, "Server Key")
	wantSig := c.hmac(serverKey, c.authMessage)
	if subtle.ConstantTimeCompare(gotSig, wantSig) != 1 {
		return errors.New("scram: server signature mismatch (wrong password or MITM)")
	}
	return nil
}

func (c *ClientConversation) hash(b []byte) []byte {
	h := c.newHash()
	h.Write(b)
	return h.Sum(nil)
}

func (c *ClientConversation) hmac(key []byte, msg string) []byte {
	h := hmac.New(c.newHash, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// escapeSCRAMName escapes "=" and "," in a SCRAM "n="/"a=" field value per RFC 5802 §5.1.
func escapeSCRAMName(s string) string {
	s = strings.ReplaceAll(s, "=", "=3D")
	s = strings.ReplaceAll(s, ",", "=2C")
	return s
}

func parseAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func randomNonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// pbkdf2 derives a key with PBKDF2-HMAC-<hash> (RFC 8018), hand-rolled to keep the module
// stdlib-only (no golang.org/x/crypto dependency). newHash selects SHA-1 or SHA-256.
func pbkdf2(newHash func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	hLen := newHash().Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, numBlocks*hLen)
	var block [4]byte
	hm := func(key, msg []byte) []byte {
		h := hmac.New(newHash, key)
		h.Write(msg)
		return h.Sum(nil)
	}
	for i := 1; i <= numBlocks; i++ {
		block[0] = byte(i >> 24)
		block[1] = byte(i >> 16)
		block[2] = byte(i >> 8)
		block[3] = byte(i)
		u := hm(password, append(append([]byte{}, salt...), block[:]...))
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iter; j++ {
			u = hm(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// saslPrep is a minimal SASLprep: for the ASCII passwords a credential broker typically mints,
// this is the identity function. We deliberately do not pull in a full stringprep table;
// non-ASCII passwords are passed through unchanged (documented limitation, matches the behavior
// this package's logic was extracted from).
func saslPrep(password string) string { return password }
