#!/usr/bin/env bash
# M7 read-API differential: restore the reference snapshot, add model rows
# (tests/models), roles and permissions (tests/rbac) and one API token per
# subject (populate.py), dump that as the shared snapshot, then run
# reference, second reference and candidate from it and compare every read
# API case (api_diff.py). The schema guard checks all databases afterwards.
# Usage: CANDIDATE_IMAGE=... [API_ONLY=endpoint,...] run.sh [--keep]
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.."
here=tests/api
export PG_PASS="$(sed -n 's/^PG_PASS=//p' reference/.env)"
export SNAPSHOT_DIR="$(mktemp -d)"
export WEB_PATH=/
export RS_API_TRACE=1
dc() { docker compose -p ak-api -f tests/differential/http/compose.yml "$@"; }
trap 'rm -rf "$SNAPSHOT_DIR"' EXIT

docker compose -f reference/compose.yml --env-file reference/.env exec -T postgresql \
  pg_dump -U authentik -d authentik -Fc > "$SNAPSHOT_DIR/snapshot.dump"
chmod 644 "$SNAPSHOT_DIR/snapshot.dump"
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc up -d ref
for _ in $(seq 1 120); do
  curl -fsS -o /dev/null "http://127.0.0.1:29000/-/health/ready/" 2>/dev/null && break
  sleep 2
done
for script in tests/models/populate.py tests/rbac/populate.py "$here/populate.py"; do
  docker exec -i ak-api-ref-1 python -m manage shell < "$script" 2>/dev/null \
    | grep '^\[populate\]' > "$SNAPSHOT_DIR/populate.log"
  if grep -v ': ok$' "$SNAPSHOT_DIR/populate.log" | grep -vq '^\[populate\] \(ok\|sampled\|tokens\)'; then
    cat "$SNAPSHOT_DIR/populate.log" >&2; echo "populate failed: $script" >&2; exit 1
  fi
done
dc exec -T ref-db pg_dump -U authentik -d authentik -Fc > "$SNAPSHOT_DIR/snapshot.dump.new"
mv "$SNAPSHOT_DIR/snapshot.dump.new" "$SNAPSHOT_DIR/snapshot.dump"
chmod 644 "$SNAPSHOT_DIR/snapshot.dump"

dc down -v >/dev/null
dc up -d
for port in 29000 29100 29200; do
  for _ in $(seq 1 120); do
    curl -fsS -o /dev/null "http://127.0.0.1:$port/-/health/ready/" 2>/dev/null && break
    sleep 2
  done
  curl -fsS -o /dev/null "http://127.0.0.1:$port/-/health/ready/"
done

status=0
python3 -I "$here/api_diff.py" --report "$here/last-report.json" ${API_ONLY:+--only "$API_ONLY"} || status=$?
for port in 25432 25532 25632; do
  rust/target/debug/ak-schema-guard verify --database-url \
    "postgres://authentik:${PG_PASS}@127.0.0.1:${port}/authentik" \
    --baseline baseline/schema/reference-schema.json || status=1
done
if [[ "${1:-}" != "--keep" ]]; then dc down -v >/dev/null; fi
exit $status
