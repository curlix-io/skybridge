#!/usr/bin/env python3
"""Stub LLM completion server for the aiclassifier demo.

Mimics the shape internal/pathlabel/aiclassifier.LLM expects: POST {"prompt": "..."} -> JSON
{"category": "...", "profile": "...", "confidence": 0.0-1.0, "rationale": "..."}.

Not a real model — inspects the prompt's field name/sample values with a few simple heuristics, so
the demo shows genuinely different responses per field without needing an API key or network
access. Swapping this for a real LLM API is a config change (LLMConfig.Endpoint/APIKey), not a code
change, per docs/AI_PATH_LABELLING_DESIGN.md's §5.1a design.
"""
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

RULES = [
    # Column-name-driven rules — the signal a content-only baseline (e.g. mask.Remote's
    # default regex entities) never sees, since it only ever inspects the value's shape.
    (re.compile(r"email", re.I), "email_fields", "full_redact", 0.97),
    (re.compile(r"ssn|social.?security", re.I), "ssn_fields", "full_redact", 0.95),
    (re.compile(r"phone|mobile|cell", re.I), "phone_fields", "full_redact", 0.9),
    (re.compile(r"\bdob\b|date.?of.?birth|birth.?date", re.I), "dob_fields", "full_redact", 0.88),
    # Content-shape rules — the same category of signal a content-only baseline does have.
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "ssn_fields", "full_redact", 0.93),
    (re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"), "email_fields", "full_redact", 0.92),
]


def signal_section(prompt: str) -> str:
    """Isolate the field-path + sample-values lines, excluding the taxonomy/instruction lines that
    follow — those always contain the literal category names (e.g. "email_fields"), which would
    otherwise make every field match "email" regardless of its actual name/samples."""
    lines = []
    for line in prompt.splitlines():
        if line.startswith("Pick exactly one category") or line.startswith("Respond with a single JSON"):
            break
        if line.startswith("Field path:") or line.startswith("- ") or line == "Sample values:":
            lines.append(line)
    return "\n".join(lines)


def classify(prompt: str):
    signal = signal_section(prompt)
    for pattern, category, profile, confidence in RULES:
        if pattern.search(signal):
            return category, profile, confidence, f"matched pattern {pattern.pattern!r}"
    return "none", "", 0.15, "no PII-shaped signal in field name or samples"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        prompt = body.get("prompt", "")
        category, profile, confidence, rationale = classify(prompt)
        resp = json.dumps({
            "category": category,
            "profile": profile,
            "confidence": confidence,
            "rationale": rationale,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def log_message(self, fmt, *args):
        print("stub-llm: " + (fmt % args))


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
