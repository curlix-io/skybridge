package studiotransport

import (
	"fmt"
	"net/url"
	"strings"
)

const defaultTrustDomain = "curlix.studio-agent"

func spiffeID(trustDomain, tenant, agent string) string {
	td := strings.TrimSpace(trustDomain)
	if td == "" {
		td = defaultTrustDomain
	}
	ag := strings.TrimSpace(agent)
	if ag == "" {
		ag = "studio-agent"
	}
	return fmt.Sprintf("spiffe://%s/tenant/%s/agent/%s", td, strings.TrimSpace(tenant), ag)
}

func parseSPIFFE(uri string) (tenant, agent string, ok bool) {
	prefix := fmt.Sprintf("spiffe://%s/tenant/", defaultTrustDomain)
	if !strings.HasPrefix(uri, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(uri, prefix)
	const marker = "/agent/"
	idx := strings.Index(rest, marker)
	if idx <= 0 {
		return "", "", false
	}
	tenant = rest[:idx]
	agent = rest[idx+len(marker):]
	if tenant == "" || agent == "" {
		return "", "", false
	}
	return tenant, agent, true
}

func spiffeURIParsed(trustDomain, tenant, agent string) (*url.URL, error) {
	return url.Parse(spiffeID(trustDomain, tenant, agent))
}
