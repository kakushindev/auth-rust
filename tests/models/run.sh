#!/usr/bin/env bash
# M4 model test: restore a snapshot of the reference DB into a scratch stack,
# populate it through Django with varied rows (populate.py), record Django's
# subclass resolution (django_classes.py), then run the ak-models tests
# against it: every row decodes, round-trips byte-equal, and resolves to the
# class Django returns. Usage: run.sh [--keep]
set -euo pipefail
cd "$(dirname "$0")/../.."
here=tests/models
export PG_PASS="$(sed -n 's/^PG_PASS=//p' reference/.env)"
export SNAPSHOT_DIR="$(mktemp -d)"
export WEB_PATH=/
dc() { docker compose -p ak-models -f tests/differential/http/compose.yml "$@"; }
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

docker exec -i ak-models-ref-1 python -m manage shell < "$here/populate.py" 2>/dev/null \
  | grep '^\[populate\]' | tee "$SNAPSHOT_DIR/populate.log"
if grep -v ': ok$' "$SNAPSHOT_DIR/populate.log" | grep -q .; then
  echo "populate failed" >&2; exit 1
fi
docker exec -i ak-models-ref-1 python -m manage shell < "$here/django_classes.py" 2>/dev/null \
  | sed -n 's/^DJANGO_CLASSES //p' > "$SNAPSHOT_DIR/classes.json"

status=0
(cd rust && AK_MODELS_DATABASE_URL="postgres://authentik:${PG_PASS}@127.0.0.1:25432/authentik" \
  AK_MODELS_DJANGO_CLASSES="$SNAPSHOT_DIR/classes.json" \
  cargo test -p ak-models -- --nocapture) || status=$?
if [[ "${1:-}" != "--keep" ]]; then dc down -v >/dev/null; fi
exit $status
