#!/usr/bin/env python3
"""Stub control-plane server for the Mongo TypeKind end-to-end demo.

Implements just enough of internal/pathlabel/remotestore's pull/push contract
(see remotestore.go's pullResponse/proposeBody) to serve one confirmed label:
  ObjectID   org1:mongo:appdb:users
  FieldPath  dob
  Category   dob_fields
  Profile    full_redact
  Source     manual

That's the label PathOverlay needs to redact the BSON datetime field this demo seeds — proving
docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B Mongo fix against a real skybridge-agent + real
MongoDB, not just a unit test.
"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

CONFIRMED_LABELS = [
    {
        "driver": "mongo",
        "database_name": "appdb",
        "object_name": "users",
        "field_path": "dob",
        "match_mode": "path",
        "category": "dob_fields",
        "profile": "full_redact",
        "source": "manual",
    },
]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/pii-path-labels":
            self.send_response(404)
            self.end_headers()
            return
        q = parse_qs(parsed.query)
        driver = q.get("driver", [""])[0]
        database = q.get("database_name", [""])[0]
        obj = q.get("object_name", [""])[0]
        matches = [
            l for l in CONFIRMED_LABELS
            if l["driver"] == driver and l["database_name"] == database and l["object_name"] == obj
        ]
        body = json.dumps({
            "organization_id": "org1",
            "labels": matches,
            "count": len(matches),
            "generated_unix": 0,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # /pii-path-labels/propose — this demo doesn't exercise proposals, just accept and discard.
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        print("stub-control-plane: " + (fmt % args))


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8091), Handler).serve_forever()
