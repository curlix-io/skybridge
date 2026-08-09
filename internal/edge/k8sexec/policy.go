// Package k8sexec runs governed, read-only kubectl commands at the customer edge. Defense-in-depth
// mirror of whatever control-plane policy dispatches these commands — the platform validates first,
// but the edge never trusts a dispatched command blindly, same posture as awsexec's read-only AWS
// CLI check.
//
// Scope: read-only structured API calls only (get/describe/logs/top/explain/version/api-resources/
// api-versions) — enforced via an allowlist of verbs, not a denylist of dangerous ones, since a
// denylist reliably misses verbs as the kubectl surface grows. Interactive verbs
// (exec/attach/cp/port-forward) and all mutating verbs (apply/patch/create/delete/scale/label/
// cordon/drain/...) are rejected — see docs/design/kubernetes-access-broker.md §2 for why brokering
// interactive sessions is a separate, harder problem deferred to a later phase.
package k8sexec

import (
	"fmt"
	"strings"
)

// Verbs that stream/attach an interactive session rather than making one structured request.
// Never allowed, regardless of read-only/write classification.
var interactiveVerbs = map[string]bool{
	"exec": true, "attach": true, "cp": true, "port-forward": true,
}

// readOnlyVerbs is the allowlist of verbs permitted through: this package brokers read-only cluster
// access only, so any verb not on this list — apply, patch, create, delete, scale, label, cordon,
// drain, and anything the kubectl surface adds later — is rejected. An allowlist is used rather than
// a denylist of dangerous verbs because a denylist reliably misses verbs as that surface grows.
var readOnlyVerbs = map[string]bool{
	"get": true, "describe": true, "logs": true, "top": true, "explain": true,
	"version": true, "api-resources": true, "api-versions": true,
}

// Substrings that would chain commands, redirect I/O, or perform substitution — same defense as
// awsexec/policy.go's forbiddenSubstrings.
var forbiddenSubstrings = []string{";", "|", "&", "<", ">", "`", "$(", "${", "\\", "\n", "\r"}

// MaxCommandLen bounds a single kubectl invocation.
const MaxCommandLen = 2000

// ParsedCommand is the verb + first non-flag argument (the resource, e.g. "pods", "ns") extracted
// from a kubectl invocation.
type ParsedCommand struct {
	Verb     string
	Resource string
	ReadOnly bool
}

// ValidateKubectlCommand reports whether command is a single, allowed kubectl invocation. Returns
// (allowed, reason, parsed); reason is a short explanation suitable for audit/agent surfacing.
func ValidateKubectlCommand(command string) (bool, string, ParsedCommand) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return false, "empty command", ParsedCommand{}
	}
	if len(cmd) > MaxCommandLen {
		return false, fmt.Sprintf("command exceeds %d characters", MaxCommandLen), ParsedCommand{}
	}
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(cmd, bad) {
			token := bad
			if bad == "\n" || bad == "\r" {
				token = "newline"
			}
			return false, "shell metacharacter not allowed: " + token, ParsedCommand{}
		}
	}

	tokens, err := shlexSplit(cmd)
	if err != nil {
		return false, "could not parse command: " + err.Error(), ParsedCommand{}
	}
	if len(tokens) < 2 || tokens[0] != "kubectl" {
		return false, "only 'kubectl' commands are permitted", ParsedCommand{}
	}

	verb := strings.ToLower(tokens[1])
	if interactiveVerbs[verb] {
		return false, "interactive verb not brokered: " + verb, ParsedCommand{}
	}
	if !readOnlyVerbs[verb] {
		return false, "verb not on read-only allowlist: " + verb, ParsedCommand{}
	}

	resource := ""
	for _, tok := range tokens[2:] {
		if strings.HasPrefix(tok, "-") {
			continue
		}
		resource = strings.ToLower(tok)
		break
	}

	return true, "ok", ParsedCommand{Verb: verb, Resource: resource, ReadOnly: true}
}

// shlexSplit is a minimal POSIX-style tokenizer: splits on whitespace honoring single and double
// quotes. Backslashes and other shell metacharacters are already rejected upstream by
// forbiddenSubstrings, so this only needs to handle simple quoting. Same implementation as
// edge/policy.go's shlexSplit (unexported per-package; kept local to avoid a cross-package
// dependency for one small helper).
func shlexSplit(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inToken := false
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inToken = true
		case c == ' ' || c == '\t':
			if inToken {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteByte(c)
			inToken = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unbalanced quote")
	}
	if inToken {
		tokens = append(tokens, cur.String())
	}
	return tokens, nil
}
