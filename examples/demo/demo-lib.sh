#!/usr/bin/env bash
# Shared helpers for the redaction demo — sourced by both examples/demo/demo-commands.sh (a
# non-interactive run-everything script, useful for manual verification) and
# examples/demo/redaction-demo.tape (the VHS recording, which types these same commands one at a
# time into a live terminal instead of piping a whole script through silently).
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
      return 1
    fi
    sleep 0.2
  done
}
cleanup_extra_agents() {
  for pid in "${extra_pids[@]:-}"; do
    [ -n "$pid" ] && kill_tree "$pid"
  done
  extra_pids=()
}
