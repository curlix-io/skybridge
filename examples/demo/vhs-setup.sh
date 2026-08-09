#!/usr/bin/env bash
# Sourced at the top of the VHS recording (examples/demo/redaction-demo.tape) so the terminal has
# demo-lib.sh's query helpers (sql/mysql_q/mongo/start_agent/wait_ready) in scope without typing
# the whole thing out on camera. Callers still see and run every actual demo command themselves —
# this just avoids retyping shared boilerplate before each one.
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source examples/demo/demo-lib.sh
clear
