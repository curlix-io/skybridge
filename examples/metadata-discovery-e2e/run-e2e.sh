#!/usr/bin/env bash
# Manual end-to-end check for metadata discovery (docs/METADATA_DISCOVERY.md): spins up real
# Postgres + MySQL + MongoDB containers seeded with the same "customers" table/collection as
# examples/demo, starts a throwaway stand-in Connector Gateway (main.go in this directory), then
# runs a real `skybridge edge` process configured with SKYBRIDGE_STUDIO_TARGETS pointing at the
# three containers. The stand-in gateway dispatches one MetadataDiscoveryRequest per driver over
# the edge's real Connect stream and checks the response — the same round trip a real Connector
# Gateway drives, minus TLS/enrollment (SKYBRIDGE_EDGE_INSECURE=true).
#
# Deliberately NOT part of `go test ./...` or CI — CLAUDE.md's testing contract keeps that suite
# hermetic; this script is the documented exception for a manual, real-database run.
#
# Usage:
#   ./examples/metadata-discovery-e2e/run-e2e.sh up      # one-shot: start, run the checks, tear
#                                                         # down, exit non-zero on failure
#   ./examples/metadata-discovery-e2e/run-e2e.sh down    # manual cleanup after an interrupted run

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

PG_CONTAINER=skybridge-mde2e-pg
PG_PORT=15533

MYSQL_CONTAINER=skybridge-mde2e-mysql
MYSQL_PORT=13407

MONGO_CONTAINER=skybridge-mde2e-mongo
MONGO_PORT=27119

GATEWAY_PORT=17100
ACCOUNT_KEY=e2e-account
DATABASE=appdb

PID_FILE=/tmp/skybridge-mde2e.pid

up() {
  echo "starting e2e Postgres..."
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$PG_CONTAINER" \
    -e POSTGRES_PASSWORD=demo -e POSTGRES_DB="$DATABASE" \
    -p "${PG_PORT}:5432" postgres:16-alpine >/dev/null
  until docker exec "$PG_CONTAINER" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
  docker exec -i "$PG_CONTAINER" psql -U postgres -d "$DATABASE" < examples/demo/seed.sql >/dev/null

  echo "starting e2e MySQL..."
  docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$MYSQL_CONTAINER" \
    -e MYSQL_ROOT_PASSWORD=demo -e MYSQL_DATABASE="$DATABASE" \
    -p "${MYSQL_PORT}:3306" mysql:8.0 >/dev/null
  echo "waiting for mysql..."
  until docker exec "$MYSQL_CONTAINER" mysqladmin ping -uroot -pdemo --silent >/dev/null 2>&1; do sleep 2; done
  until docker exec -i "$MYSQL_CONTAINER" mysql -uroot -pdemo "$DATABASE" < examples/demo/seed.mysql.sql 2>/dev/null; do sleep 2; done

  echo "starting e2e Mongo..."
  docker rm -f "$MONGO_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$MONGO_CONTAINER" -p "${MONGO_PORT}:27017" mongo:7.0 >/dev/null
  until docker exec "$MONGO_CONTAINER" mongosh --quiet --eval "db.runCommand({ping:1})" >/dev/null 2>&1; do sleep 1; done
  docker exec -i "$MONGO_CONTAINER" mongosh --quiet < examples/demo/seed.mongo.js >/dev/null

  : > "$PID_FILE"

  echo "starting stand-in Connector Gateway on :${GATEWAY_PORT}..."
  # Process substitution (not a `| tee` pipeline) so $! below is the actual gateway program's pid,
  # not tee's -- a backgrounded `cmd | tee &` would make `wait`/$? report tee's (always-0) exit
  # status instead of the gateway's real pass/fail verdict.
  go run ./examples/metadata-discovery-e2e \
    -listen ":${GATEWAY_PORT}" -account "$ACCOUNT_KEY" -database "$DATABASE" -timeout 60s \
    > >(tee /tmp/skybridge-mde2e-gateway.log) 2>&1 &
  GATEWAY_PID=$!
  echo "$GATEWAY_PID" >> "$PID_FILE"
  sleep 1

  targets=$(cat <<JSON
[
  {"db_type":"postgres","aws_account_id":"${ACCOUNT_KEY}","database_name":"${DATABASE}","host":"localhost:${PG_PORT}","user":"postgres","password":"demo","sslmode":"disable"},
  {"db_type":"mysql","aws_account_id":"${ACCOUNT_KEY}","database_name":"${DATABASE}","host":"localhost:${MYSQL_PORT}","user":"root","password":"demo"},
  {"db_type":"mongo","aws_account_id":"${ACCOUNT_KEY}","database_name":"${DATABASE}","host":"localhost:${MONGO_PORT}"}
]
JSON
)

  echo "starting skybridge edge..."
  # SKYBRIDGE_STUDIO_AUTO=0: setting SKYBRIDGE_STUDIO_TARGETS otherwise makes NormalizeEdge derive
  # a Studio Gateway address from GatewayAddr (internal/config/normalize.go) -- with our
  # non-standard gateway port that just ends up dialing the same stand-in gateway a second time
  # for an unrelated protocol (logged, harmless "Unimplemented", but pure noise here).
  SKYBRIDGE_EDGE_GATEWAY="localhost:${GATEWAY_PORT}" \
  SKYBRIDGE_EDGE_INSECURE=true \
  SKYBRIDGE_ORG_ID=e2e-org \
  SKYBRIDGE_EDGE_ID=e2e-edge \
  SKYBRIDGE_STUDIO_TARGETS="$targets" \
  SKYBRIDGE_STUDIO_AUTO=0 \
  go run ./cmd/skybridge edge >/tmp/skybridge-mde2e-edge.log 2>&1 &
  echo $! >> "$PID_FILE"

  echo "waiting for the gateway's verdict..."
  wait "$GATEWAY_PID"
  status=$?
  down
  if [ "$status" -ne 0 ]; then
    echo "e2e FAILED — see /tmp/skybridge-mde2e-edge.log and /tmp/skybridge-mde2e-gateway.log"
    exit "$status"
  fi
  echo "e2e PASSED"
}

# kill_tree kills a pid and its children — `go run &` backgrounds the wrapper, which execs a
# separate compiled-binary child; killing just the wrapper's pid would leave that child running.
kill_tree() {
  local pid="$1"
  for child in $(pgrep -P "$pid" 2>/dev/null); do
    kill_tree "$child"
  done
  kill "$pid" >/dev/null 2>&1 || true
}

down() {
  if [ -f "$PID_FILE" ]; then
    while read -r pid; do
      [ -n "$pid" ] && kill_tree "$pid"
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  fi
  docker rm -f "$PG_CONTAINER" "$MYSQL_CONTAINER" "$MONGO_CONTAINER" >/dev/null 2>&1 || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 {up|down}" >&2; exit 1 ;;
esac
