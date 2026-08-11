#!/usr/bin/env bash
# Self-contained recorded demo: starts the docker/Presidio/DB stack, shows the agent's config
# options, runs the baseline column-overlay/content-detection scenarios across all three supported
# DB types, then demonstrates a custom user-authored overlay file and three deeper redaction
# scenarios (JSON blob in a text column, a nested Mongo document, and a partial-mask anonymizer
# config), and tears everything down at the end — one script, one asciinema recording.
#
#   ./examples/demo/demo-commands.sh
#
# (Run ./examples/demo/run-demo.sh up/down directly if you want to poke at the stack without
# re-running the whole script.)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
export PAGER=cat
export PATH="/opt/homebrew/opt/mysql-client@9.3/bin:$PATH"

SELECT_SQL="select id, employee_id, name, email, ssn from customers;"

sql() { psql -P pager=off "postgres://postgres:demo@$1/appdb" -c "$SELECT_SQL"; }
# --ssl-mode=DISABLED is required against the agent port (13306): the MySQL wire proxy can't parse
# a TLS-encrypted stream, so it drops to unmasked passthrough if the client negotiates TLS (see
# internal/wire/mysql/mysql.go). The raw port (13307, straight to mysqld) keeps its normal TLS.
mysql_q() { mysql -h 127.0.0.1 -P "$2" -uroot -pdemo appdb -e "$SELECT_SQL" 2>/dev/null; }
mysql_masked() { mysql -h 127.0.0.1 -P "$2" --ssl-mode=DISABLED -uroot -pdemo appdb -e "$SELECT_SQL" 2>/dev/null; }
mongo() { mongosh --quiet "mongodb://$1/appdb" --eval 'db.customers.find({}, {_id:0}).forEach(d => print(JSON.stringify(d)))'; }

section() { echo; echo "$ # $1"; }

# ---- extra short-lived agent lifecycle (custom-overlay + partial-mask scenarios) ----
# kill_tree kills a pid and its children — `go run &` backgrounds the `go run` wrapper, which execs
# a separate compiled-binary child; killing just the wrapper's pid leaves the actual skybridge-agent
# process (and its listening port) running.
kill_tree() {
  local pid="$1"
  for child in $(pgrep -P "$pid" 2>/dev/null); do
    kill_tree "$child"
  done
  kill "$pid" >/dev/null 2>&1 || true
}
extra_pids=()
extra_agent_count=0
start_agent() { # env-assignments-string
  extra_agent_count=$((extra_agent_count + 1))
  eval "$1 go run ./cmd/skybridge agent >/tmp/skybridge-demo-extra-agent-${extra_agent_count}.log 2>&1 &"
  extra_pids+=("$!")
}
wait_ready() { # port
  local port="$1" tries=0
  until nc -z localhost "$port" 2>/dev/null; do
    tries=$((tries + 1))
    if [ "$tries" -gt 50 ]; then
      echo "agent on $port never became ready" >&2
      exit 1
    fi
    sleep 0.2
  done
}
cleanup() {
  for pid in "${extra_pids[@]:-}"; do
    [ -n "$pid" ] && kill_tree "$pid"
  done
  ./examples/demo/run-demo.sh down
}
trap cleanup EXIT

section "0a. Start the demo stack (Postgres + MySQL + MongoDB + Presidio + 3 Skybridge agents)"
./examples/demo/run-demo.sh up

section "0b. skybridge-agent --help — see the agent's configuration options"
go run ./cmd/skybridge agent --help

section "1. Postgres, raw (no agent)"
sql localhost:15433

section "2. Postgres, masked — email/ssn redacted by the column overlay"
sql localhost:15432

section "3. Postgres, masked — employee_id/name are EXCLUDED (no overlay rule for them)"
psql -P pager=off "postgres://postgres:demo@localhost:15432/appdb" -c "select employee_id, name from customers;"

section "4. Postgres, free text: 'notes' has no overlay rule, but Presidio content-detection still redacts the phone number"
psql -P pager=off "postgres://postgres:demo@localhost:15432/appdb" -c "select notes from customers where id = 1;"

section "5. MySQL, raw (no agent)"
mysql_q x 13307

section "6. MySQL, masked — email/ssn redacted by the column overlay"
mysql_masked x 13306

section "7. MySQL, masked — employee_id/name are EXCLUDED (no overlay rule for them)"
mysql -h 127.0.0.1 -P 13306 --ssl-mode=DISABLED -uroot -pdemo appdb -e "select employee_id, name from customers;" 2>/dev/null

section "8. MongoDB, raw (no agent)"
mongo localhost:27019

section "9. MongoDB, masked — email/ssn redacted; employee_id/name EXCLUDED (no overlay rule)"
mongo localhost:27020

section "10. Custom overlay file — author your own SKYBRIDGE_PII_OVERLAY_FILE and point the agent at it"
cat examples/demo/custom-overlay.yaml
start_agent "SKYBRIDGE_DB_TYPE=postgres SKYBRIDGE_UPSTREAM=localhost:15433 SKYBRIDGE_LISTEN=:15436 SKYBRIDGE_PII_OVERLAY_FILE=$(pwd)/examples/demo/custom-overlay.yaml"
wait_ready 15436
echo "-- with custom-overlay.yaml, 'name' is now redacted too (contrast with scenario 3) --"
psql -P pager=off "postgres://postgres:demo@localhost:15436/appdb" -c "select employee_id, name, email from customers;"

section "11. JSON blob in a text column — Presidio finds PII inside the JSON string, no overlay rule involved"
psql -P pager=off "postgres://postgres:demo@localhost:15433/appdb" -c "select id, metadata from customers where id = 3;"
echo "-- masked: --"
psql -P pager=off "postgres://postgres:demo@localhost:15432/appdb" -c "select id, metadata from customers where id = 3;"

section "12. Nested MongoDB document — profile.email is redacted despite being nested (bare-key overlay match); order.total is untouched"
echo "-- raw: --"
mongo localhost:27019
echo "-- masked: --"
mongo localhost:27020

section "13. Partial-mask anonymizer — mask part of a phone/SSN instead of a full [redacted] replace"
PARTIAL_ANONYMIZERS='{"PHONE_NUMBER":{"type":"mask","masking_char":"*","chars_to_mask":6,"from_end":true},"US_SSN":{"type":"mask","masking_char":"*","chars_to_mask":7,"from_end":false}}'
export SKYBRIDGE_MASK_ANONYMIZERS="$PARTIAL_ANONYMIZERS"
start_agent "SKYBRIDGE_DB_TYPE=postgres SKYBRIDGE_UPSTREAM=localhost:15433 SKYBRIDGE_LISTEN=:15437 SKYBRIDGE_MASK_ANALYZE_URL=http://localhost:13000/analyze SKYBRIDGE_MASK_ANONYMIZE_URL=http://localhost:13001/anonymize"
wait_ready 15437
unset SKYBRIDGE_MASK_ANONYMIZERS
echo "-- with partial-mask anonymizers, only part of the phone number / SSN is masked --"
psql -P pager=off "postgres://postgres:demo@localhost:15437/appdb" -c "select notes from customers where id = 1;"

section "0c. Tear down the demo stack"
# (handled by the EXIT trap above)
