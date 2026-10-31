#!/usr/bin/env bash
# M6 permission differential: restore a reference snapshot into a scratch
# stack, add rows of every model type (tests/models/populate.py) and the
# roles, groups, users and model/object permissions in populate.py, record
# Django's permission decisions (rbac_decide.py: has_perm with and without
# objects, get_objects_for_user, ObjectFilter, DRF ObjectPermissions,
# permission_required) for every subject, and check that ak-rbac decides
# the same. Usage: run.sh [--keep]
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.."
here=tests/rbac
export PG_PASS="$(sed -n 's/^PG_PASS=//p' reference/.env)"
export SNAPSHOT_DIR="$(mktemp -d)"
export WEB_PATH=/
dc() { docker compose -p ak-rbac -f tests/differential/http/compose.yml "$@"; }
trap '[[ -n "${KEEP_DIR:-}" ]] && cp -R "$SNAPSHOT_DIR/." "$KEEP_DIR/"; rm -rf "$SNAPSHOT_DIR"' EXIT

docker compose -f reference/compose.yml --env-file reference/.env exec -T postgresql \
  pg_dump -U authentik -d authentik -Fc > "$SNAPSHOT_DIR/snapshot.dump"
chmod 644 "$SNAPSHOT_DIR/snapshot.dump"
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc up -d ref
for _ in $(seq 1 120); do
  curl -fsS -o /dev/null "http://127.0.0.1:29000/-/health/ready/" 2>/dev/null && break
  sleep 2
done
container=ak-rbac-ref-1

docker exec -i "$container" python -m manage shell < tests/models/populate.py 2>/dev/null \
  | grep '^\[populate\]' > "$SNAPSHOT_DIR/models-populate.log"
if grep -v ': ok$' "$SNAPSHOT_DIR/models-populate.log" | grep -q .; then
  echo "model populate failed" >&2; exit 1
fi
docker exec -i "$container" python -m manage shell < "$here/populate.py" 2>/dev/null | grep -q '^\[populate\] ok$' \
  || { echo "rbac populate failed" >&2; exit 1; }
docker exec -i "$container" python -m manage shell < "$here/rbac_decide.py" 2>/dev/null \
  | sed -n 's/^RBAC_DECISIONS //p' > "$SNAPSHOT_DIR/rbac.json"
test -s "$SNAPSHOT_DIR/rbac.json" || { echo "no Django decisions" >&2; exit 1; }

status=0
(cd rust && AK_RBAC_DATABASE_URL="postgres://authentik:${PG_PASS}@127.0.0.1:25432/authentik" \
  AK_RBAC_DJANGO="$SNAPSHOT_DIR/rbac.json" \
  cargo test -p ak-rbac -- --nocapture) || status=$?
if [[ "${1:-}" != "--keep" ]]; then dc down -v >/dev/null; fi
exit $status
