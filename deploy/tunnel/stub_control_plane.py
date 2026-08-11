#!/usr/bin/env python3
"""Stub control-plane server for the local tunnel smoke test (docker-compose.tunnel.yml).

skybridge-gateway fails closed on every client connection if it has no TargetResolver
(internal/gateway/httptarget.go's NoopTargetResolver always returns ErrTargetNotFound) — a
control-plane URL is not optional for relaying, only session recording and wire-admit are
best-effort/no-op without one. This stub implements the wire-targets GET route
(internal/gateway/httptarget.go's HTTPTargetResolver contract) so a docker-compose-only
gateway + agent/edge setup can resolve a target and relay real wire traffic to UPSTREAM_ADDR.

Once SKYBRIDGE_GW_CONTROL_PLANE_URL is set at all, the gateway also wires up HTTPWireAdmitter and
HTTPStore (cmd/skybridge-gateway/main.go) against the same base URL — unlike NoopTargetResolver,
their Noop counterparts aren't the default once a control-plane URL is configured, so this stub
must answer POST /api/v1/wire-admit (200 = admitted) and the session-lifecycle POSTs
(internal/gateway/httpstore.go's contract) too, or the gateway's default http.Server 501s on POST
and the wire-admit call fails, rejecting every client connection before it ever reaches Resolve.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

UPSTREAM_ADDR = os.environ.get("UPSTREAM_ADDR", "127.0.0.1:5432")
UPSTREAM_DB_TYPE = os.environ.get("UPSTREAM_DB_TYPE", "postgres")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/v1/wire-targets":
            self.send_response(404)
            self.end_headers()
            return
        q = parse_qs(parsed.query)
        org_id = q.get("organization_id", [""])[0]
        body = json.dumps({
            "organization_id": org_id,
            "targets": [{
                "name": "db",
                "addr": UPSTREAM_ADDR,
                "db_type": UPSTREAM_DB_TYPE,
                "resource_role_id": "local-tunnel-test",
            }],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/sessions":
            body = json.dumps({"id": "local-tunnel-test-session"}).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # wire-admit and session-close/transcript calls all just need a 2xx with no body.
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        print("stub-control-plane: " + (fmt % args))


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8091), Handler).serve_forever()
