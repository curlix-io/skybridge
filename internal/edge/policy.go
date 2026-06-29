package edge

import (
	"fmt"
	"strings"
)

// Read-only AWS CLI allowlist, mirroring the control plane's read-only command policy. The edge
// enforces the code-shipped defaults as a defense-in-depth check; per-org overrides are applied
// platform-side before dispatch.
//
// The policy is intentionally conservative: it favors rejecting a borderline command over allowing a
// mutating or credential-exfiltrating one. Only a single, analyzable `aws <service> <read-op>`
// invocation is permitted.

// MaxCommandLen bounds a single CLI invocation.
const MaxCommandLen = 1200

// Substrings that would chain commands, redirect I/O, or perform substitution — any of these means
// the command is no longer a single analyzable invocation.
var forbiddenSubstrings = []string{";", "|", "&", "<", ">", "`", "$(", "${", "\\", "\n", "\r"}

// Global options that consume the following token as their value (skipped when locating service/op).
var valueFlags = map[string]bool{
	"--region": true, "--output": true, "--profile": true, "--endpoint-url": true,
	"--query": true, "--ca-bundle": true, "--cli-read-timeout": true, "--cli-connect-timeout": true,
	"--color": true, "--page-size": true, "--max-items": true, "--starting-token": true,
	"--cli-input-json": true, "--cli-input-yaml": true,
}

var readVerbPrefixes = []string{"describe", "list", "get", "lookup", "search", "batch-get", "head", "scan", "query"}

var sensitiveOperations = map[string]bool{
	"get-secret-value": true, "get-login-password": true, "get-authorization-token": true,
	"get-password-data": true, "get-session-token": true, "get-federation-token": true,
}

var deniedFlags = map[string]bool{"--profile": true, "--endpoint-url": true}

var deniedArgTokens = map[string]bool{"--with-decryption": true}

// ValidateReadOnlyAWSCommand reports whether command is a single, read-only AWS CLI invocation.
// It returns (allowed, reason); reason is a short explanation suitable for audit/agent surfacing.
func ValidateReadOnlyAWSCommand(command string) (bool, string) {
	cmd := strings.TrimSpace(command)
	if cmd == "" {
		return false, "empty command"
	}
	if len(cmd) > MaxCommandLen {
		return false, fmt.Sprintf("command exceeds %d characters", MaxCommandLen)
	}
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(cmd, bad) {
			token := fmt.Sprintf("%q", bad)
			if bad == "\n" || bad == "\r" {
				token = "newline"
			}
			return false, "shell metacharacter not allowed: " + token
		}
	}

	tokens, err := shlexSplit(cmd)
	if err != nil {
		return false, "could not parse command: " + err.Error()
	}
	if len(tokens) == 0 {
		return false, "empty command"
	}
	if tokens[0] != "aws" {
		return false, "only 'aws' commands are permitted"
	}

	for _, tok := range tokens[1:] {
		low := strings.ToLower(tok)
		if deniedFlags[low] {
			return false, "flag not allowed: " + tok
		}
		if i := strings.IndexByte(low, '='); i >= 0 && deniedFlags[low[:i]] {
			return false, "flag not allowed: " + tok[:strings.IndexByte(tok, '=')]
		}
		if deniedArgTokens[low] {
			return false, "argument not allowed: " + tok
		}
	}

	service, operation := serviceAndOperation(tokens[1:])
	if service == "" {
		return false, "missing AWS service (e.g. ec2, rds, s3)"
	}
	if operation == "" {
		return false, "missing AWS operation"
	}

	// `aws s3 ...` (high-level) only exposes read via `ls`; api reads go through s3api.
	if service == "s3" {
		if operation == "ls" {
			return true, "ok"
		}
		return false, fmt.Sprintf("'aws s3 %s' is not read-only (use 'aws s3 ls' or 's3api' read calls)", operation)
	}

	if !isReadOperation(operation) {
		return false, fmt.Sprintf("operation '%s' is not on the read-only allowlist", operation)
	}
	return true, "ok"
}

// SplitCommand tokenizes a shell-style command into argv. Call it only after
// ValidateReadOnlyAWSCommand has accepted the command (it assumes no backslash/metacharacters).
func SplitCommand(command string) ([]string, error) {
	return shlexSplit(strings.TrimSpace(command))
}

func isReadOperation(operation string) bool {
	op := strings.ToLower(operation)
	if sensitiveOperations[op] {
		return false
	}
	for _, prefix := range readVerbPrefixes {
		if op == prefix || strings.HasPrefix(op, prefix+"-") {
			return true
		}
	}
	return false
}

// serviceAndOperation finds the service and operation, skipping global option flags and their values.
func serviceAndOperation(args []string) (string, string) {
	var bare []string
	skipNext := false
	for _, tok := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(tok, "-") {
			name := tok
			if i := strings.IndexByte(tok, '='); i >= 0 {
				name = tok[:i]
			}
			if valueFlags[name] && !strings.Contains(tok, "=") {
				skipNext = true
			}
			continue
		}
		bare = append(bare, tok)
		if len(bare) >= 2 {
			break
		}
	}
	service := ""
	operation := ""
	if len(bare) >= 1 {
		service = strings.ToLower(bare[0])
	}
	if len(bare) >= 2 {
		operation = strings.ToLower(bare[1])
	}
	return service, operation
}

// shlexSplit is a minimal POSIX-style tokenizer: splits on whitespace honoring single and double
// quotes. Backslashes and other shell metacharacters are already rejected upstream by
// forbiddenSubstrings, so this only needs to handle simple quoting.
func shlexSplit(s string) ([]string, error) {
	var tokens []string
	var cur strings.Builder
	inToken := false
	quote := byte(0) // 0, '\'' or '"'
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
