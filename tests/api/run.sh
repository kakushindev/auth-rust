#!/usr/bin/env bash
# M7 read-API differential: restore the reference snapshot, add model rows
# (tests/models), roles and permissions (tests/rbac) and one API token per
# subject (populate.py), dump that as the shared snapshot, then run
# reference, second reference and candidate from it and compare every read
# API case (api_diff.py). The schema guard checks all databases afterwards.
# Usage: CANDIDATE_IMAGE=... [API_ONLY=endpoint,...] [API_JOBS=n] run.sh [--keep]
# API_JOBS (default 8) runs that many tokens concurrently; each token keeps
# the suite order, and 1 is the fully sequential run.
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
# Session cookies (sessions.py) on the reference, then the states that
# need SQL: a deactivated user and an expired session.
python3 -I "$here/sessions.py" http://127.0.0.1:29000 > "$SNAPSHOT_DIR/sessions.json"
expired_sid="$(python3 -I -c 'import base64,json,sys; c=json.load(open(sys.argv[1]))["session-expired"].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(c+"="*(-len(c)%4)))["sid"])' "$SNAPSHOT_DIR/sessions.json")"
dc exec -T ref-db psql -U authentik -d authentik -qc \
  "UPDATE authentik_core_user SET is_active = false WHERE username = 'm8-sess-inactive'; UPDATE authentik_core_session SET expires = now() - interval '1 hour' WHERE session_key = '${expired_sid}';" >/dev/null
export API_SESSIONS="$SNAPSHOT_DIR/sessions.json"
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
