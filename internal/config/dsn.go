package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// EdgeKey is the decoded form of a SKYBRIDGE_KEY connection string — one copy-pasteable value
// instead of six separate SKYBRIDGE_* env vars for the common case, a pattern other access proxies
// use for their own equivalent single-value connection strings.
//
// Format: skybridge://<org_id>:<enrollment_token>@<gateway-host>[?edge_id=<id>&region=<aws-region>&ca=<base64-pem>]
// The connector-gateway (7100) and enroll (7101) ports are fixed by convention and derived from
// the bare host — they are never part of the DSN. The CA bundle, when present, is the mTLS trust
// root PEM standard-base64-encoded (it contains newlines and `+`/`/` bytes that don't survive
// unescaped in a URL query value) — the encode side must apply the same convention.
type EdgeKey struct {
	OrgID           string
	EnrollmentToken string
	GatewayHost     string
	EdgeID          string
	AWSRegion       string
	CABundlePEM     []byte
}

// parseEdgeKey decodes a SKYBRIDGE_KEY value. An empty input returns the zero value and no error —
// callers treat that as "no key provided," not a parse failure, so discrete SKYBRIDGE_* vars keep
// working unchanged when SKYBRIDGE_KEY is unset.
func parseEdgeKey(raw string) (EdgeKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return EdgeKey{}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return EdgeKey{}, fmt.Errorf("invalid SKYBRIDGE_KEY: %w", err)
	}
	if u.Scheme != "skybridge" {
		return EdgeKey{}, fmt.Errorf("invalid SKYBRIDGE_KEY: expected skybridge:// scheme, got %q", u.Scheme)
	}
	if u.Host == "" {
		return EdgeKey{}, fmt.Errorf("invalid SKYBRIDGE_KEY: missing gateway host")
	}
	if u.User == nil || u.User.Username() == "" {
		return EdgeKey{}, fmt.Errorf("invalid SKYBRIDGE_KEY: missing org id")
	}
	token, _ := u.User.Password()
	q := u.Query()
	var caBundle []byte
	if rawCA := q.Get("ca"); rawCA != "" {
		caBundle, err = base64.StdEncoding.DecodeString(rawCA)
		if err != nil {
			return EdgeKey{}, fmt.Errorf("invalid SKYBRIDGE_KEY: malformed ca parameter: %w", err)
		}
	}
	return EdgeKey{
		OrgID:           u.User.Username(),
		EnrollmentToken: token,
		GatewayHost:     u.Host,
		EdgeID:          q.Get("edge_id"),
		AWSRegion:       q.Get("region"),
		CABundlePEM:     caBundle,
	}, nil
}

// hostPort appends the fixed port to a bare gateway host, or returns "" when host is empty.
func hostPort(host, port string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	return host + ":" + port
}
