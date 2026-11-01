#!/usr/bin/env bash
# M8 event differential: restore a reference snapshot into a scratch stack,
# add users and a brand (event_populate.py), record the Event rows and tasks
# Django writes for Event.new(...).from_http(...) over many request
# variants (event_decide.py) and the state its session middlewares leave
# when they log a session out (logout_populate.py, logout_decide.py), and
# check that ak-events writes the same.
# Usage: run.sh [--keep]
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.."
here=tests/events
export PG_PASS="$(sed -n 's/^PG_PASS=//p' reference/.env)"
export SNAPSHOT_DIR="$(mktemp -d)"
export WEB_PATH=/
dc() { docker compose -p ak-events -f tests/differential/http/compose.yml "$@"; }
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
container=ak-events-ref-1

docker exec -i "$container" python -m manage shell < "$here/event_populate.py" 2>/dev/null | grep -q '^\[populate\] ok$' \
  || { echo "populate failed" >&2; exit 1; }
docker exec -i "$container" python -m manage shell < "$here/event_decide.py" 2>/dev/null \
  | sed -n 's/^EVENT_DECISIONS //p' > "$SNAPSHOT_DIR/events.json"
test -s "$SNAPSHOT_DIR/events.json" || { echo "no Django decisions" >&2; exit 1; }
docker exec -i "$container" python -m manage shell < "$here/logout_populate.py" 2>/dev/null \
  | sed -n 's/^LOGOUT_CASES //p' > "$SNAPSHOT_DIR/logout-cases.json"
test -s "$SNAPSHOT_DIR/logout-cases.json" || { echo "logout populate failed" >&2; exit 1; }
# A Python literal, not JSON: values may be null.
{ printf 'CASES = '; python3 -c 'import json, sys; print(repr(json.load(open(sys.argv[1]))))' "$SNAPSHOT_DIR/logout-cases.json"
  cat "$here/logout_decide.py"; } \
  | docker exec -i "$container" python -m manage shell 2>/dev/null \
  | sed -n 's/^LOGOUT_DECISIONS //p' > "$SNAPSHOT_DIR/logout.json"
test -s "$SNAPSHOT_DIR/logout.json" || { echo "no Django logout decisions" >&2; exit 1; }
mkdir -p "$SNAPSHOT_DIR/geoip"
docker cp "$container:/geoip/GeoLite2-ASN.mmdb" "$SNAPSHOT_DIR/geoip/" >/dev/null
docker cp "$container:/geoip/GeoLite2-City.mmdb" "$SNAPSHOT_DIR/geoip/" >/dev/null

status=0
(cd rust && AK_EVENTS_DB="postgres://authentik:${PG_PASS}@127.0.0.1:25432/authentik" \
  AK_EVENTS_DJANGO="$SNAPSHOT_DIR/events.json" AK_GEOIP_DIR="$SNAPSHOT_DIR/geoip" \
  AK_EVENTS_LOGOUT="$SNAPSHOT_DIR/logout.json" \
  AK_EVENTS_SECRET_KEY="$(sed -n 's/^AUTHENTIK_SECRET_KEY=//p' ../reference/.env)" \
  cargo test -p ak-events --test event --test logout -- --nocapture) || status=$?
if [[ "${1:-}" != "--keep" ]]; then dc down -v >/dev/null; fi
exit $status
