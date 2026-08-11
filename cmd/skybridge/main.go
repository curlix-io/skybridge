package main

import (
	"fmt"
	"os"
)

const usage = `skybridge — egress-only wire proxy + edge tool dispatch for governed native database access.

Usage:
  skybridge <role> [flags]

Roles:
  agent      egress agent: listener OR tunnel mode
  gateway    relay gateway: agent endpoint + client listeners
  edge       unified edge: call-home transport(s) + AWS/k8s tool exec + optional wire proxy
  labeller   periodic AI-based path-label scan job

Run "skybridge <role> --help" for role-specific configuration (all via SKYBRIDGE_* env vars).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	role, args := os.Args[1], os.Args[2:]
	switch role {
	case "agent":
		runAgent(args)
	case "gateway":
		runGateway(args)
	case "edge":
		runEdge(args)
	case "labeller":
		runLabeller(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "skybridge: unknown role %q\n\n", role)
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}
