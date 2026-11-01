#!/usr/bin/env bash
# M7 read-API differential: restore the reference snapshot, add model rows
# (tests/models), roles and permissions (tests/rbac) and one API token per
# subject (populate.py), dump that as the shared snapshot, then run
# reference, second reference and candidate from it and compare every read
# API case (api_diff.py). The schema guard checks all databases afterwards.
# Then the M8 write differential (tests/writes) runs on the same stacks.
# Usage: CANDIDATE_IMAGE=... [API_ONLY=endpoint,...] [API_JOBS=n] [WEB_WORKERS=n]
#        [API_FRESH=1] [API_SUITES="reads writes"] [WRITE_ONLY=group,...]
#        [CAND_BINARY=path] run.sh [--keep]
# API_SUITES picks the suites; the schema guard always runs. WRITE_ONLY
# runs some write groups (write_diff.py --only); CAND_BINARY runs the
# candidate image with that binary (tests/writes/quick.sh).
# API_JOBS (default 8) runs that many tokens concurrently; each token keeps
# the suite order, and 1 is the fully sequential run. Each case asks the
# three stacks at once. WEB_WORKERS sets gunicorn's workers on every stack
# alike (authentik's default, 2). The fixture is cached (see below).
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.."
here=tests/api
export PG_PASS="$(sed -n 's/^PG_PASS=//p' reference/.env)"
export SNAPSHOT_DIR="$(mktemp -d)"
export WEB_PATH=/
export RS_API_TRACE=1
# CAND_BINARY mounts a locally built binary into the candidate image.
compose_files=(-f tests/differential/http/compose.yml)
if [[ -n "${CAND_BINARY:-}" ]]; then compose_files+=(-f tests/differential/http/compose.binary.yml); fi
dc() { docker compose -p ak-api "${compose_files[@]}" "$@"; }
trap 'rm -rf "$SNAPSHOT_DIR"' EXIT

# The fixture: the reference snapshot plus model rows, roles, tokens and
# session cookies (and the SQL states they need). Building it takes minutes,
# so it is cached, keyed by everything it is made of: the reference
# database's exact contents (a plain pg_dump, byte for byte), the image, the
# populate and session scripts, this script and the compose file. A cached
# fixture is reused for at most 6 hours, well inside the lifetime of the
# sessions and the "future" tokens it holds. API_FRESH=1 always rebuilds.
sid() { python3 -I -c 'import base64,json,sys; c=json.load(open(sys.argv[1]))[sys.argv[2]].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(c+"="*(-len(c)%4)))["sid"])' "$SNAPSHOT_DIR/sessions.json" "$1"; }
build_fixture() {
  cp "$SNAPSHOT_DIR/base.dump" "$SNAPSHOT_DIR/snapshot.dump"
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
  local expired_sid="$(python3 -I -c 'import base64,json,sys; c=json.load(open(sys.argv[1]))["session-expired"].split(".")[1]; print(json.loads(base64.urlsafe_b64decode(c+"="*(-len(c)%4)))["sid"])' "$SNAPSHOT_DIR/sessions.json")"
  local moved_sids="'$(sid session-moved-plain)','$(sid session-moved-super)','$(sid session-moved-bearer)'"
  dc exec -T ref-db psql -U authentik -d authentik -qc \
    "UPDATE authentik_core_user SET is_active = false WHERE username = 'm8-sess-inactive'; UPDATE authentik_core_session SET expires = now() - interval '1 hour' WHERE session_key = '${expired_sid}'; UPDATE authentik_core_session SET last_ip = '10.9.9.9' WHERE session_key IN (${moved_sids});" >/dev/null
  local bound_sid="$(sid session-bound)"
  docker exec -i ak-api-ref-1 python -m manage shell -c "
from authentik.core.sessions import SessionStore
s = SessionStore(session_key='${bound_sid}')
s['authentik/stages/user_login/binding/net'] = 'bind_asn'
s['last_ip'] = '8.8.8.8'
s.save()" >/dev/null 2>&1
  dc exec -T ref-db pg_dump -U authentik -d authentik -Fc > "$SNAPSHOT_DIR/snapshot.dump.new"
  mv "$SNAPSHOT_DIR/snapshot.dump.new" "$SNAPSHOT_DIR/snapshot.dump"
  chmod 644 "$SNAPSHOT_DIR/snapshot.dump"
}
phase_start=$(date +%s)
timing() { echo "[timing] $1 $(( $(date +%s) - phase_start ))s"; phase_start=$(date +%s); }
cache_root="${API_CACHE_DIR:-$HOME/.cache/auth-rust/api-fixture}"
mkdir -p "$cache_root"
find "$cache_root" -mindepth 1 -maxdepth 1 -type d -mmin +360 -exec rm -rf {} +
# One dump of the reference: hashed (as the SQL it restores to, which has no
# dump timestamp, without pg_dump's random \restrict token) and, on a miss,
# the base of the fixture.
docker compose -f reference/compose.yml --env-file reference/.env exec -T postgresql \
  pg_dump -U authentik -d authentik -Fc > "$SNAPSHOT_DIR/base.dump"
# The reference's worker keeps rewriting its task, schedule and cache tables;
# their data (and sequences) are left out of the key, though not out of the
# fixture: a fixture from an older copy of them is as valid a fixture.
churn='authentik_tasks_schedules_schedule|authentik_tasks_task|authentik_tasks_tasklog|authentik_tasks_workerstatus|django_postgres_cache_cacheentry'
restore() { docker run --rm -v "$SNAPSHOT_DIR:/d:ro" docker.io/library/postgres:16-alpine pg_restore "$@"; }
restore -l /d/base.dump | grep -Ev "(TABLE DATA|SEQUENCE SET) public (${churn})(_[a-z_]*_seq)? " > "$SNAPSHOT_DIR/base.list"
key="$({
  restore -L /d/base.list -f - /d/base.dump | grep -Ev '^\\(un)?restrict ' | shasum -a 256
  docker image inspect --format '{{.Id}}' ghcr.io/goauthentik/server:2026.2.7
  cat tests/models/populate.py tests/rbac/populate.py "$here/populate.py" "$here/sessions.py" \
    "$here/run.sh" tests/differential/http/compose.yml
} | shasum -a 256 | cut -d' ' -f1)"
cache="$cache_root/$key"
if [[ -z "${API_FRESH:-}" && -s "$cache/snapshot.dump" && -s "$cache/sessions.json" \
      && -n "$(find "$cache/snapshot.dump" -mmin -360)" ]]; then
  cp "$cache/snapshot.dump" "$cache/sessions.json" "$SNAPSHOT_DIR/"
  echo "[fixture] cached ${key:0:12}"
else
  build_fixture
  mkdir -p "$cache"
  cp "$SNAPSHOT_DIR/snapshot.dump" "$SNAPSHOT_DIR/sessions.json" "$cache/"
  echo "[fixture] built ${key:0:12}"
fi
timing fixture
moved_sids="'$(sid session-moved-plain)','$(sid session-moved-super)','$(sid session-moved-bearer)'"
bound_sid="$(sid session-bound)"
inactive_sid="$(sid session-inactive)"
export API_SESSIONS="$SNAPSHOT_DIR/sessions.json"

dc down -v >/dev/null
dc up -d
for port in 29000 29100 29200; do
  for _ in $(seq 1 120); do
    curl -fsS -o /dev/null "http://127.0.0.1:$port/-/health/ready/" 2>/dev/null && break
    sleep 2
  done
  curl -fsS -o /dev/null "http://127.0.0.1:$port/-/health/ready/"
done

timing stacks
status=0
suites=" ${API_SUITES:-reads writes} "
if [[ "$suites" == *" reads "* ]]; then
python3 -I "$here/api_diff.py" --report "$here/last-report.json" ${API_ONLY:+--only "$API_ONLY"} || status=$?
timing cases
# The moved sessions after their save: Django's on ref, Rust's on cand.
for db in ref-db cand-db; do
  dc exec -T "$db" psql -U authentik -d authentik -Atc \
    "SELECT json_agg(json_build_object('key', session_key, 'last_ip', host(last_ip), 'expiring', expiring, 'expires', extract(epoch from expires), 'data', encode(session_data, 'base64'))) FROM authentik_core_session WHERE session_key IN (${moved_sids})" \
    > "$SNAPSHOT_DIR/sessions-$db.json"
done
state="$(python3 -I -c 'import json,sys; print(json.dumps({"ref": json.load(open(sys.argv[1])), "cand": json.load(open(sys.argv[2]))}))' \
  "$SNAPSHOT_DIR/sessions-ref-db.json" "$SNAPSHOT_DIR/sessions-cand-db.json" \
  | docker exec -i ak-api-ref-1 python -m manage shell -c "$(cat "$here/session_state.py")" 2>/dev/null \
  | grep '^\[session-state\]' || true)"
echo "$state"
grep -q '^\[session-state\] ok$' <<<"$state" || status=1
# The middlewares' logouts (inactive user, broken binding): Django's state on
# ref against Rust's on cand. Logout events (the default brand's pk is
# random per process), the outposts' session-end tasks and the flushed
# sessions. Dispatch tasks are not counted: Go's brand watcher polls the
# brands API, whose 500s here add system_exception events on ref only.
for db in ref-db cand-db; do
  dc exec -T "$db" psql -U authentik -d authentik -Atc \
    "SELECT json_build_object(
       'events', (SELECT json_agg(e ORDER BY e::text) FROM (SELECT app, context, host(client_ip) AS ip, \"user\", brand - 'pk' AS brand,
                  round(extract(epoch from expires - created)) AS ttl, expiring FROM authentik_events_event WHERE action = 'logout') e),
       'tasks', (SELECT count(*) FROM authentik_tasks_task WHERE actor_name = 'authentik.outposts.tasks.outpost_session_end'),
       'sessions', (SELECT count(*) FROM authentik_core_session WHERE session_key IN ('${bound_sid}', '${inactive_sid}')))" \
    > "$SNAPSHOT_DIR/logout-$db.json"
done
if python3 -I -c 'import json,sys; a,b=(json.load(open(p)) for p in sys.argv[1:3]); print("[logout-state]", "ok" if a == b and a["sessions"] == 0 else "MISMATCH"); sys.exit(a != b or a["sessions"] != 0)' \
  "$SNAPSHOT_DIR/logout-ref-db.json" "$SNAPSHOT_DIR/logout-cand-db.json"; then :; else
  status=1; diff <(python3 -m json.tool "$SNAPSHOT_DIR/logout-ref-db.json") <(python3 -m json.tool "$SNAPSHOT_DIR/logout-cand-db.json") | head -40
fi
fi
# The write differential records every row change through triggers, which
# come off again before the schema guard.
if [[ "$suites" == *" writes "* ]]; then
  for db in ref-db ref2-db cand-db; do
    dc exec -T "$db" psql -q -U authentik -d authentik -v ON_ERROR_STOP=1 < tests/writes/capture.sql
  done
  python3 -I tests/writes/write_diff.py --report tests/writes/last-report.json ${WRITE_ONLY:+--only "$WRITE_ONLY"} || status=1
  for db in ref-db ref2-db cand-db; do
    dc exec -T "$db" psql -q -U authentik -d authentik -v ON_ERROR_STOP=1 < tests/writes/uncapture.sql
  done
  timing writes
fi
for port in 25432 25532 25632; do
  rust/target/debug/ak-schema-guard verify --database-url \
    "postgres://authentik:${PG_PASS}@127.0.0.1:${port}/authentik" \
    --baseline baseline/schema/reference-schema.json || status=1
done
timing checks
if [[ "${1:-}" != "--keep" ]]; then dc down -v >/dev/null; fi
exit $status
