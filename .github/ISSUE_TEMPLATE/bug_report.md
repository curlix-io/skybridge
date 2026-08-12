---
name: Bug report
about: Report unexpected behavior in Skybridge
title: ""
labels: bug
assignees: ""
---

**Describe the bug**
A clear description of what's wrong.

**Role and deployment shape**
- Role: agent / gateway / edge / labeller
- Deployment shape: listener / tunnel / edge
- Database: postgres / mysql / mongodb / snowflake

**Configuration**
Relevant `SKYBRIDGE_*` env vars (redact tokens, secrets, and credentials).

**To reproduce**
Steps to reproduce the behavior.

**Expected behavior**
What you expected to happen instead.

**Logs**
Relevant log output (with debug logging enabled if possible). Redact any raw PII, tokens, or
credentials before pasting — see this repo's security model in CLAUDE.md.

**Version**
Output of `skybridge --version` or the commit SHA you built from.

**Additional context**
Anything else relevant (OS, Go version, network topology, etc).
