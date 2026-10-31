#!/usr/bin/env bash
# M5 request-identity differential: restore a reference snapshot into a
# scratch stack, add the rows in populate.py, record Django's decisions for
# every vector in vectors.json (host validation, brand, tenant, bearer
# authentication) and for every session cookie sessions.py makes (real
# logins, impersonation, logout, crafted JWTs), and check that ak-auth
# decides the same.
# Usage: run.sh [--keep]
set -euo pipefail
cd "$(dirname "$0")/../.."
here=tests/auth
export PG_PASS="$(sed -n 's/^PG_PASS=//p' reference/.env)"
export SNAPSHOT_DIR="$(mktemp -d)"
export WEB_PATH=/
dc() { docker compose -p ak-auth -f tests/differential/http/compose.yml "$@"; }
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
container=ak-auth-ref-1

docker exec -i "$container" python -m manage shell < "$here/populate.py" 2>/dev/null | grep -q '^\[populate\] ok$' \
  || { echo "populate failed" >&2; exit 1; }
{ printf 'VECTORS = '; cat "$here/vectors.json"; echo; cat "$here/django_decide.py"; } \
  | docker exec -i "$container" python -m manage shell 2>/dev/null \
  | sed -n 's/^DJANGO_DECISIONS //p' > "$SNAPSHOT_DIR/django.json"
test -s "$SNAPSHOT_DIR/django.json" || { echo "no Django decisions" >&2; exit 1; }

# Sessions: made over HTTP, then a user deactivated and a session expired.
secret_key="$(sed -n 's/^AUTHENTIK_SECRET_KEY=//p' reference/.env)"
python3 "$here/sessions.py" http://127.0.0.1:29000 "$secret_key" \
  "$(sed -n 's/^AUTHENTIK_BOOTSTRAP_PASSWORD=//p' reference/.env)" > "$SNAPSHOT_DIR/cookies.json"
expire="$(python3 -c 'import json, sys; print(next(c["sid"] for c in json.load(open(sys.argv[1])) if c["name"] == "real:to-expire"))' "$SNAPSHOT_DIR/cookies.json")"
docker exec -i ak-auth-ref-db-1 psql -q -v ON_ERROR_STOP=1 -U authentik -d authentik <<SQL
UPDATE authentik_core_user SET is_active = false WHERE username = 'm5-deactivate';
UPDATE authentik_core_session SET expires = now() - interval '1 minute' WHERE session_key = '$expire';
SQL
# A Python literal, not JSON: the cookies hold null.
{ printf 'COOKIES = '; python3 -c 'import json, sys; print(repr(json.load(open(sys.argv[1]))))' "$SNAPSHOT_DIR/cookies.json"
  cat "$here/session_decide.py"; } \
  | docker exec -i "$container" python -m manage shell 2>/dev/null \
  | sed -n 's/^SESSION_DECISIONS //p' > "$SNAPSHOT_DIR/session-django.json"
test -s "$SNAPSHOT_DIR/session-django.json" || { echo "no Django session decisions" >&2; exit 1; }

status=0
(cd rust && AK_AUTH_DATABASE_URL="postgres://authentik:${PG_PASS}@127.0.0.1:25432/authentik" \
  AK_AUTH_VECTORS="$PWD/../$here/vectors.json" AK_AUTH_DJANGO="$SNAPSHOT_DIR/django.json" \
  AK_AUTH_COOKIES="$SNAPSHOT_DIR/cookies.json" AK_AUTH_SESSION_DJANGO="$SNAPSHOT_DIR/session-django.json" \
  AK_AUTH_SECRET_KEY="$secret_key" \
  AK_AUTH_IPC_KEY="$(docker exec "$container" sh -c 'cat ${TMPDIR:-/tmp}/authentik-core-ipc.key')" \
  cargo test -p ak-auth -- --nocapture) || status=$?
if [[ "${1:-}" != "--keep" ]]; then dc down -v >/dev/null; fi
exit $status
