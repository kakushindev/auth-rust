#!/usr/bin/env bash
# Snapshot the reference DB, start reference + candidate stacks restored from
# it, run the HTTP differential harness, then check both databases against the
# schema baseline. Usage: run.sh [--keep]   (--keep leaves the stacks running)
set -euo pipefail
cd "$(dirname "$0")/../../.."
here=tests/differential/http
export PG_PASS="$(sed -n 's/^PG_PASS=//p' reference/.env)"
export SNAPSHOT_DIR="${SNAPSHOT_DIR:-$(mktemp -d)}"
dc() { docker compose -p ak-diff -f "$here/compose.yml" "$@"; }

# The snapshot holds password hashes and tokens: it never leaves the temp dir.
docker compose -f reference/compose.yml --env-file reference/.env exec -T postgresql \
  pg_dump -U authentik -d authentik -Fc > "$SNAPSHOT_DIR/snapshot.dump"
chmod 644 "$SNAPSHOT_DIR/snapshot.dump"

dc down -v --remove-orphans >/dev/null 2>&1 || true
dc up -d
for port in 29000 29100 29200; do
  for _ in $(seq 1 120); do
    curl -fsS -o /dev/null "http://127.0.0.1:$port/-/health/ready/" && break
    sleep 2
  done
  curl -fsS -o /dev/null "http://127.0.0.1:$port/-/health/ready/"
done

status=0
python3 -I "$here/harness.py" --report "$here/last-report.json" || status=$?

# Both databases must still match the schema baseline after the run.
guard=rust/target/debug/ak-schema-guard
for port in 25432 25532 25632; do
  "$guard" verify --database-url "postgres://authentik:${PG_PASS}@127.0.0.1:${port}/authentik" \
    --baseline baseline/schema/reference-schema.json || status=1
done
if [[ "${1:-}" != "--keep" ]]; then dc down -v >/dev/null; fi
rm -rf "$SNAPSHOT_DIR"
exit $status
