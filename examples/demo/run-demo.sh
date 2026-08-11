#!/usr/bin/env bash
# Spins up an isolated demo Postgres + MySQL + Mongo + a standalone Presidio pair, then three
# Skybridge agents (one per db type) with column-overlay redaction on
# (SKYBRIDGE_PII_OVERLAY_FILE) and content-detection masking on
# (SKYBRIDGE_MASK_ANALYZE_URL/_ANONYMIZE_URL), seeds sample PII rows, and leaves everything
# running so examples/demo/demo-commands.sh can capture a live before/after across all three
# supported database types.
#
# Usage:
#   ./examples/demo/run-demo.sh up      # start db/agent trios + Presidio, seed data
#   ./examples/demo/demo-commands.sh    # run + record the demo commands
#   ./examples/demo/run-demo.sh down    # tear down

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

PG_CONTAINER=skybridge-demo-pg
PG_PORT=15433
PG_AGENT_PORT=15432

MYSQL_CONTAINER=skybridge-demo-mysql
MYSQL_PORT=13307
MYSQL_AGENT_PORT=13306

MONGO_CONTAINER=skybridge-demo-mongo
MONGO_PORT=27019
MONGO_AGENT_PORT=27020

PID_FILE=/tmp/skybridge-demo-agents.pid

up() {
  echo "starting Presidio (content-detection layer)..."
  docker compose -f examples/demo/docker-compose.demo.yml up -d
  echo "waiting for Presidio..."
  until curl -sf http://localhost:13000/health >/dev/null 2>&1 && curl -sf http://localhost:13001/health >/dev/null 2>&1; do
    sleep 1
  done

  echo "starting demo Postgres..."
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$PG_CONTAINER" \
    -e POSTGRES_PASSWORD=demo -e POSTGRES_DB=appdb \
    -p "${PG_PORT}:5432" postgres:16-alpine >/dev/null
  until docker exec "$PG_CONTAINER" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
  docker exec -i "$PG_CONTAINER" psql -U postgres -d appdb < examples/demo/seed.sql >/dev/null

  echo "starting demo MySQL..."
  docker rm -f "$MYSQL_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$MYSQL_CONTAINER" \
    -e MYSQL_ROOT_PASSWORD=demo -e MYSQL_DATABASE=appdb \
    -p "${MYSQL_PORT}:3306" mysql:8.0 >/dev/null
  echo "waiting for mysql..."
  until docker exec "$MYSQL_CONTAINER" mysqladmin ping -uroot -pdemo --silent >/dev/null 2>&1; do sleep 2; done
  # mysqladmin ping can succeed before the server accepts real connections during init; retry the seed.
  until docker exec -i "$MYSQL_CONTAINER" mysql -uroot -pdemo appdb < examples/demo/seed.mysql.sql 2>/dev/null; do sleep 2; done

  echo "starting demo Mongo..."
  docker rm -f "$MONGO_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$MONGO_CONTAINER" -p "${MONGO_PORT}:27017" mongo:7.0 >/dev/null
  until docker exec "$MONGO_CONTAINER" mongosh --quiet --eval "db.runCommand({ping:1})" >/dev/null 2>&1; do sleep 1; done
  docker exec -i "$MONGO_CONTAINER" mongosh --quiet < examples/demo/seed.mongo.js >/dev/null

  : > "$PID_FILE"

  echo "starting skybridge-agent (postgres) on :${PG_AGENT_PORT}..."
  SKYBRIDGE_DB_TYPE=postgres \
  SKYBRIDGE_UPSTREAM="localhost:${PG_PORT}" \
  SKYBRIDGE_LISTEN=":${PG_AGENT_PORT}" \
  SKYBRIDGE_PII_OVERLAY_FILE="$(pwd)/examples/pii-overlay.yaml" \
  SKYBRIDGE_MASK_ANALYZE_URL="http://localhost:13000/analyze" \
  SKYBRIDGE_MASK_ANONYMIZE_URL="http://localhost:13001/anonymize" \
  go run ./cmd/skybridge agent >/tmp/skybridge-demo-pg-agent.log 2>&1 &
  echo $! >> "$PID_FILE"

  echo "starting skybridge-agent (mysql) on :${MYSQL_AGENT_PORT}..."
  SKYBRIDGE_DB_TYPE=mysql \
  SKYBRIDGE_UPSTREAM="localhost:${MYSQL_PORT}" \
  SKYBRIDGE_LISTEN=":${MYSQL_AGENT_PORT}" \
  SKYBRIDGE_PII_OVERLAY_FILE="$(pwd)/examples/pii-overlay.yaml" \
  go run ./cmd/skybridge agent >/tmp/skybridge-demo-mysql-agent.log 2>&1 &
  echo $! >> "$PID_FILE"

  echo "starting skybridge-agent (mongodb) on :${MONGO_AGENT_PORT}..."
  SKYBRIDGE_DB_TYPE=mongodb \
  SKYBRIDGE_UPSTREAM="localhost:${MONGO_PORT}" \
  SKYBRIDGE_LISTEN=":${MONGO_AGENT_PORT}" \
  SKYBRIDGE_PII_OVERLAY_FILE="$(pwd)/examples/pii-overlay.yaml" \
  go run ./cmd/skybridge agent >/tmp/skybridge-demo-mongo-agent.log 2>&1 &
  echo $! >> "$PID_FILE"

  sleep 2
  echo "ready:"
  echo "  postgres raw    localhost:${PG_PORT}       masked localhost:${PG_AGENT_PORT}"
  echo "  mysql    raw    localhost:${MYSQL_PORT}     masked localhost:${MYSQL_AGENT_PORT}"
  echo "  mongodb  raw    localhost:${MONGO_PORT}     masked localhost:${MONGO_AGENT_PORT}"
}

# kill_tree kills a pid and its children — needed because `go run &` backgrounds the `go run`
# wrapper, which execs a separate compiled-binary child; killing just the wrapper's pid leaves the
# actual skybridge-agent process (and its listening port) running.
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
  docker compose -f examples/demo/docker-compose.demo.yml down >/dev/null 2>&1 || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *) echo "usage: $0 {up|down}" >&2; exit 1 ;;
esac
