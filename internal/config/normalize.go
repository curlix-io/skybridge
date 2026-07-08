package config

import "strings"

// swapGatewayPort replaces :fromPort with :toPort on a host:port address.
func swapGatewayPort(addr, fromPort, toPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasSuffix(addr, ":"+fromPort) {
		return strings.TrimSuffix(addr, ":"+fromPort) + ":" + toPort
	}
	if !strings.Contains(addr, ":") {
		return addr + ":" + toPort
	}
	return addr
}

// NormalizeEdge fills derived Studio gateway settings from the connector gateway when
// SKYBRIDGE_STUDIO_AUTO is enabled (default) and Studio dispatch is configured.
func NormalizeEdge(e *Edge) {
	if e == nil {
		return
	}
	wantStudio := strings.TrimSpace(e.StudioTargetsJSON) != "" ||
		strings.TrimSpace(e.StudioEnrollmentToken) != "" ||
		strings.TrimSpace(e.StudioGateway) != ""
	if !wantStudio {
		return
	}
	if !truthy(env("SKYBRIDGE_STUDIO_AUTO", "1")) {
		return
	}
	if strings.TrimSpace(e.StudioGateway) == "" && strings.TrimSpace(e.GatewayAddr) != "" {
		e.StudioGateway = swapGatewayPort(e.GatewayAddr, "7100", "7200")
	}
	if strings.TrimSpace(e.StudioEnrollGateway) == "" {
		if strings.TrimSpace(e.EnrollTarget) != "" {
			e.StudioEnrollGateway = swapGatewayPort(e.EnrollTarget, "7101", "7201")
		} else if strings.TrimSpace(e.GatewayAddr) != "" {
			e.StudioEnrollGateway = swapGatewayPort(e.GatewayAddr, "7100", "7201")
		}
	}
	if strings.TrimSpace(e.StudioEnrollmentToken) == "" {
		e.StudioEnrollmentToken = e.EnrollToken
	}
	if strings.TrimSpace(e.StudioAgentID) == "" {
		e.StudioAgentID = e.EdgeID
	}
}
