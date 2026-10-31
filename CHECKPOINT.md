# Checkpoint

Durable resume point for the authentik → Rust rewrite. Update at the end of every batch.

## Batch 20 — 2026-10-31

- M7 is **done**. Added `rbac/permissions/assigned_by_roles` (with `model_choices()` generated into `registry.rs` from `baseline/inventory/model_choices.json`) and `core/application_entitlements`. A full run of the 15 viewsets has 13 192 cases; 13 188 are equal and the 4 others are Django-served `users/me/`. Rust answered 12 676.
- Carve-outs, with their target milestones, are in COMPATIBILITY_REPORT ("M7 closed"): `core/applications` and `user_consent` go to M9/M9b, `authenticated_sessions` to M8, and `rbac/permissions/roles` waits for the model `__str__` port.

### Exact next action
M8: write endpoints and their side effects (signals, events, cache invalidation), starting with sessions (the session cookie is still declined everywhere). That also brings `authenticated_sessions`.

## Batch 19 — 2026-10-31

- M7 part 5: `core/tokens`, `events/events` (with the R2 `autocomplete`, including the `SELECT DISTINCT app` options), `events/notifications` and `events/rules` are served from Rust. The full parallel run has 12 393 cases; all are equal except Django-served `users/me/`. The 13 differences that run found in notifications and rules were fixed, and those two endpoints re-run at 1 241/1 241 equal.
- Bugs found and fixed:
  - DRF registers `rbac/permissions/roles` and `/assigned_by_roles` ahead of `rbac/permissions`, so those paths are now declined;
  - `ModelChoiceField` does check for NUL;
  - a join that the filterset adds must not exist yet when `ObjectFilter` runs its `exists()` (new `DjangoQuery::demote_join`).
- The harness now runs tokens in parallel (`API_JOBS`, default 8). On one image it produced the same buckets and the same Rust-served set as the sequential run, and a full run takes about 15 minutes instead of about 50.
- `core/applications` is deferred to the policy-engine milestone: its list evaluates policies, and expression policies are Python.

### Exact next action
`core/authenticated_sessions`, `core/application_entitlements`, `rbac/permissions/roles`, `rbac/permissions/assigned_by_roles`; then close M7 with a list of what stays on Django and why.

## Batch 18 — 2026-10-31

- M7 part 4: `core/users` and `core/groups` are served from Rust, including the reproduced R2 `autocomplete`. The full read-API run is **9 431 equal + 3 nondeterministic of 9 435**, with 9 004 answered by Rust; the one difference is `users/me/`, which Django serves and whose `system_permissions` order varies. The schema guard is clean.
- New in `ak-api`:
  - `cache.rs`: Django's Postgres cache (key format, pickle subset, `get`/`has_key`/`touch`, with writes queued until the response is certain);
  - `avatar.rs`: every `get_avatar` mode, lxml-identical initials SVGs;
  - `UserSerializer`, `GroupSerializer`, `PartialGroupSerializer`, `PartialUserSerializer` and `RelatedGroupSerializer`, with Django's exact prefetch SQL;
  - more django-filter kinds (startswith, isnull, `MultipleChoiceFilter`, int- and field-keyed `ModelMultipleChoiceFilter`);
  - `run.sh` takes `API_ONLY`.
- Found while doing it:
  - `etree.tostring` writes non-ASCII as character references;
  - `IsoDateTimeField` rejects a blank value;
  - `touch()` cuts the 8-hour avatar cache entry back to 300 s on every hit.

### Exact next action
Port `core/tokens` (`user_obj` through `UserSerializer`), then `core/applications` and `events/events` (QL `autocomplete` with the `SELECT DISTINCT app` options).

## Batch 17 — 2026-10-31

- M7 part 3: four more viewsets read from Rust: `core/brands`, `events/transports`, `propertymappings/notification` and `crypto/certificatekeypairs`. The whole read API passes `tests/api/run.sh` with **7 089/7 089 equal** (6 925 Rust-served); the schema guard is clean on all 3 databases.
- New `ak-api` pieces:
  - `filters.rs`: generic django-filter fields (`CharFilter`, `ChoiceFilter`, both boolean widgets, `UUIDFilter`, FK and m2m `ModelChoiceFilter`);
  - `drf::datetime`;
  - `DjangoQuery` versions of `ObjectFilter` and `SearchFilter`;
  - router support for `detail=False` actions (`brands/current/`, `certificatekeypairs/generate/`).
- Found while doing it:
  - Booleans generated from `filterset_fields` use `BooleanWidget` (`true/false/1/0`), while declared filters use `NullBooleanSelect` (`2/3`).
  - Django picks which of several invalid m2m values to report in per-process hash order, so Rust declines that case.
  - `jsonb` stores `1e20` as an integer, which orjson cannot render (Django 500).
- **R2 decided: reproduce** the Enterprise QL `autocomplete` (owner). It is specified in MIGRATION_PLAN R2: users and groups are static, and events adds `SELECT DISTINCT app … ORDER BY app`.

### Exact next action
Port a `UserSerializer` (avatar providers; gravatar is a cached outbound check). Then serve `core/users` and `core/groups` with the reproduced `autocomplete`, followed by `core/tokens`, `core/applications`, `events/events` and the remaining `events` viewsets (`events/rules` embeds `GroupSerializer`).

## Batch 16 — 2026-10-31

- M7 part 2: `rbac/permissions` (`DjangoQuery` emits Django's exact SQL so ordering ties match) and `rbac/initial_permissions` (nested `PermissionSerializer`, `Permission` default ordering) are verified. All RBAC read endpoints pass: **3 570/3 570 equal**, 3 524 Rust-served, schema clean.
- New `ak-api` pieces: `json::render_jsonb` (jsonb → orjson, `ryu` floats), `registry.rs` (verbose names, generated), `views/common.rs`.
- Next, `core/brands` needs generic django-filter field types (`UUIDFilter`, `ModelChoiceFilter`, `ModelMultipleChoiceFilter`, whose `frozenset` validation order is nondeterministic upstream), m2m search via `EXISTS` with `distinct`, and the `attributes` jsonb. `core/tokens` and every endpoint embedding `user_obj` wait for a `UserSerializer` port: its `avatar` resolves the tenant's avatar providers, and gravatar is a cached outbound HTTP check.

## Batch 15 — 2026-10-31

- **M7 part 1**: new crate `rust/crates/ak-api` (DRF/Django read pipeline: admission and declines, content negotiation, token authentication, `ObjectPermissions`, Enterprise-search backend order with DRF `SearchFilter` fallback, `ObjectFilter`, django-filter primitives, ordering, `AutocompletePagination`, Python parsing semantics), wired in `src/server/core.rs` `read_api` with routes registered in `compat.rs`.
- `GET /api/v3/rbac/roles/` and `/{pk}/` are verified: `tests/api/run.sh` shows **1 870/1 870 equal** and 1 831 Rust-served. Found while doing it: Enterprise search reorders the backends and adds `autocomplete`; django-filter's `NumberFilter` caps at the float `1e50`; `NullBooleanSelect` ignores `1`; an invalid `groups` UUID is Django's own 500.
- **Owner decision needed (R2)**: the `autocomplete` of `core/users`, `core/groups` and `events/events` comes from Enterprise code.

### Exact next action
M7 continues with the endpoints not touched by R2: `rbac/permissions` (Django-identical SQL, because permission names repeat and tie order is observable), `rbac/initial_permissions`, `core/tokens`, `core/brands`, `core/applications`, then `crypto/certificatekeypairs` and the `events` viewsets other than `events/events`. Each needs its serializer port and a case list in `tests/api/api_diff.py`.

## Batch 14 — 2026-10-31

- **M6 done**: new crate `rust/crates/ak-rbac`, which ports authentik's role-based permissions through the `ak-guardian` fork. It covers `has_perm`/`has_perms`, `get_objects_for_user`, `ObjectFilter`, DRF `ObjectPermissions` and `permission_required`.
- `tests/rbac/run.sh` runs the model fixture plus `tests/rbac/populate.py` (roles, group hierarchy, superuser groups, object permissions on two rows of every model). Its 38k decisions for 14 subjects are identical to Django's (`rbac_decide.py`).
- Behaviour reproduced:
  - guardian counts duplicate grants;
  - inactive superusers see every object;
  - inactive users still get object rows from `get_objects_for_user`;
  - text-pk models raise `ProgrammingError`, and uncastable `object_pk` raises `DataError`;
  - service accounts get empty lists instead of 403.
- Lint/tests clean for ak-rbac; stacks torn down. A full run takes about 5 minutes, mostly in Django's side.

### Exact next action
M7: read-only API endpoints (`core`, `rbac`, `crypto`, `events` list/retrieve) in the Rust server. The request pipeline combines `ak-auth` (identity, CSRF, cookies) and `ak-rbac` (permissions, with `get_objects_for_user` as a SQL filter). Responses must match DRF's serializers, filtering, ordering, search and pagination. Check them per operation against the reference over HTTP, including 401/403/404.

## Batch 13 — 2026-10-31

- **M5 done.** New crate `rust/crates/ak-geoip`: a MaxMind reader plus `geoip2` models; `tests/geoip/run.sh` shows 4,328 addresses identical on the image's GeoLite2 databases. New `ak-auth` modules:
  - `client_ip` (with the outpost override);
  - `binding` (bound sessions);
  - `csrf` (Django and DRF);
  - `cookie` (Morsel rendering, session/CSRF `process_response`, JWT encoding);
  - `url` (CPython `urlsplit`/`quote`, Django URI helpers, the login redirect).
- `session::resolve` now applies bindings and returns the session state the response needs.
- `tests/auth/run.sh` adds:
  - bound real sessions requested from other IPs: 81 cookies plus 75 response cookies identical;
  - `web_decide.py`: CSRF, tokens, cookies, `process_response`, `is_secure`, redirects, 1,613 binding rechecks, 77 client IPs, all identical;
  - 13 HTTP answers on the wire reproduced;
  - 455 CPython `urlsplit` vectors.
- Found on the way: the flow executor does not enforce CSRF (a view-level fact for M9), and Python's cookie quoting escapes `;` and `,`.
- Lint/tests: ak-auth, ak-geoip, ak-pickle, ak-passwords and ak-models pass clippy and their tests. A workspace-wide build on macOS still stops at `aws-lc-fips-sys` (known). Stacks are torn down.

### Exact next action
M6: RBAC + guardian permissions. Port `authentik.rbac` (roles, `ObjectPermissions`, `InitialPermissionsMiddleware`) and django-guardian's object permissions on top of `ak-models`. Then a permission-matrix differential for all models × roles, using the same pattern: Django decides in a rolled-back transaction, and the Rust test compares.

## Batch 12 — 2026-10-31

- **M5 part 2, sessions**: `ak_auth::session::resolve` (PyJWT cookie decode with CPython's base64/JSON/`int()` semantics in `python.rs`, session store, `AuthenticatedSession`, inactive logout, impersonation) plus the new crate `rust/crates/ak-pickle` (safe pickle reader, 39 CPython vectors).
- `tests/auth/run.sh` now also logs in over HTTP (`sessions.py`), deactivates/expires in SQL and records Django's middleware decisions (`session_decide.py`): 54 cookies and 33 session-pickle keys identical. Found and fixed on real data: `QueryDict` (dict subclass via `__setitem__`) and `SimpleLazyObject` in session pickles.
- CPython vectors (`tests/auth/gen_python_vectors.py`) must be generated inside the image: the JSON recursion limit is stack-dependent. `run.sh` needs `~/.cargo/bin` on PATH.

### Exact next action
M5 part 2b: CSRF (`CsrfViewMiddleware`: `authentik_csrf` cookie, `X-authentik-CSRF` header, masked tokens, origin/referer checks) and `BoundSessionMiddleware`'s network/GeoIP binding checks (ASN/GeoIP readers), with response cookie setting; differential like `tests/auth/run.sh`.

## Batch 11 — 2026-10-31

- **M5 part 1, request identity**: new crate `rust/crates/ak-auth` (host validation, brand, tenant, bearer token auth) using Django's own SQL. `tests/auth/run.sh`: 25 hosts and 34 Authorization headers decide identically to Django, covering every outcome path.
- Deferred to M8 and recorded in the report: the writes Django does while authenticating (expired-token deletion with cascade and audit event; outpost user creation).
- All crates clippy-clean; stacks torn down (`docker compose down` needs `PG_PASS`/`SNAPSHOT_DIR`/`WEB_PATH`).

### Exact next action
M5 part 2: sessions. Port authentik's session store (`authentik.core.sessions`: session key cookie, `Session.session_data` encoding, expiry), `AuthenticatedSession`, `BoundSessionMiddleware`, CSRF (`CsrfViewMiddleware`: cookie and masked token), impersonation, logout and concurrent login. Then the cookie/session differential with expiry, logout and concurrent login.

## Batch 10 — 2026-10-31

- **M4 done (storage layer)**: `rust/crates/ak-models`, generated by `scripts/gen_models.py` from the schema snapshot (80 row types, exact column types, jsonb as `RawValue`), with generic fetch/insert/update and multi-table-inheritance resolution.
- `tests/models/run.sh`: Django populates a snapshot with every model type → 282 rows in 80 tables decode and round-trip byte-equal (update and delete/re-insert, FKs checked, seeded difference detected); subclass resolution matches Django for all 79 rows, including an Enterprise provider.
- Teardown note: `docker compose -p ak-diff … down` needs `PG_PASS` and `SNAPSHOT_DIR` set, or it fails silently with output discarded; ad-hoc teardowns had been leaving stacks up.

### Exact next action
M5: sessions and authentication middleware (session cookie, token auth, CSRF, tenant/brand resolution) on top of `ak-models`, with a cookie/session differential including expiry, logout and concurrent login.

## Batch 9 — 2026-10-31

- **Owner decisions recorded** (`docs/MIGRATION_PLAN.md` R2, R5, M18–M20; memory): the embedded outpost reports Go's hello values; Enterprise is kept separate (17 rows "Excluded (separate)", matrix regenerated); product name **Gapura** with logo, wordmark and favicon in `branding/`; source github.com/kakushindev/auth-rust, image `ghcr.io/kakushindev/auth-rust:main-<n>`.
- **Outpost hello**: Django's stored `OutpostState` is identical to the reference. HTTP 504/0 different, forwarded 21/0, outpost requests identical.
- M2 is now done with no open owner decisions; the only remaining open item is the approximate `%q` for non-ASCII format characters.

### Exact next action
M4: `ak-models` read models (User, Group, Application, Provider/Source multi-table inheritance, Token, Brand, Tenant). Every row of a populated reference DB must decode, and round-trip writes must leave rows byte-equal.

## Batch 8 — 2026-10-31

- **Forwarded-header differential observed in Django's request log** (`forwarded.py`, run by `run.sh`): 21/21 identical with the harness host trusted and untrusted (`TRUSTED_CIDRS=127.0.0.1/32`); the full HTTP harness is also 0 different in untrusted mode.
- **502s** carry Go's transport error and JSON escaping (`backend_down.sh`: identical). **gunicorn** launches exactly as gounicorn does (`authentik-core.sock`, `--pid` file).
- **Embedded outpost** talks to core over TCP at `http://<listen.http><web.path>` like Go (API, websocket, backchannel), fetches root config, and sends Go's websocket headers. Django-side requests identical (`outpost_requests.py`), also under `web.path`.
- **M2 is done** apart from the owner decision on the outpost hello fields. All differentials: 0 different. Clippy clean; 110 unit tests pass (+1 needing PostgreSQL).

### Exact next action
M4: `ak-models` read models for User, Group, Application, Provider/Source (multi-table inheritance), Token, Brand and Tenant. Each must decode every row of the populated reference DB, and round-trip writes must leave rows byte-equal (acceptance in `docs/MIGRATION_PLAN.md`). Owner decisions pending: outpost hello fields; R2 Enterprise; the M18 name/logo files; the M19 registry org.

## Batch 7 — 2026-10-30

- **Brand TLS (:9443)** ported from Go `brand_tls`/`web_tls.go`/`CryptoStore`: per-ClientHello config (`ak-axum` `LazyTlsAcceptor`), Go's brand selection quirks, `RequestClientCert`, the GOFIPS TLS surface with Go's cipher/signature order and tickets, and Go's fallback certificate. `tests/differential/tls/brands.sh`: reference and candidate identical (11 SNIs plus the full TLS probe).
- **Non-default `web.path`**: `/` redirect, NotFound outside the prefix, prefixed health probe, ping only at the default path. `WEB_PATH=/authentik/ tests/differential/http/run.sh`: 534 cases, 0 different.
- Default HTTP differential 504/0 different, metrics differential 0 differences, schema guard clean, clippy clean (core and core+proxy). The healthcheck test no longer mutates `TMPDIR`, which had broken temp-dir tests under plain `cargo test`.
- Production note: apps.mysoc.id terminates TLS at HAProxy and proxies to :9000, so :9443 is not in its live path.

### Exact next action
M2 remainder: the embedded outpost's transport (Go: TCP to `listen.http`; Rust: the unix socket) and its hello fields (owner decision pending), Go's exact 502 text, and untrusted-proxy header paths beyond unit tests. Then start M4 (`ak-models` read models).

## Batch 6 — 2026-10-30

- **Plan**: owner decisions recorded as R5 and milestones M18 (rebrand: name and logo), M19 (CI/CD) and M20 (auto-deploy to apps.mysoc.id via Flux image automation in omb-ipb-si/infrastructure), all after the 100 % Rust rewrite (M17). Still owed by the owner: the new name, logo files, and the registry org/image.
- **Health checks**: ported Go's `healthcheck` (server: HEAD over TCP; worker: PID-file signal 0). Upstream Rust's worker check needed the server socket, which would have restart-looped every production worker pod. Exit codes match the reference in 4/4 container cases.
- **Metrics :9300**: `/metrics` only, Go-rendered registry plus process/promhttp collectors, then Django's metrics fetched with Go's key file. Also writes the IPC key and fixes the request-duration observation scope and outpost gauge labels. Metrics differential `tests/differential/metrics/compare.py`: 0 differences over 47 families (`go_*` runtime families excluded).
- HTTP differential 504 cases: 496 equal / 8 nondeterministic / 0 different; schema guard clean; clippy clean (core and core+proxy).

### Exact next action
M2 remainder in `docs/COMPATIBILITY_REPORT.md`: brand TLS (SQL against the 2026.2.7 schema), then non-default `web.path`. Then start M4 (`ak-models` read models).

## Batch 5 — 2026-10-30

- **Listen addresses**: scalar (2026.2.7) or list config. Entries resolve like Go's `net.Listen` and bind like `favoriteAddrFamily` (a wildcard is `[::]` dual-stack). Accepted sockets get Go's `TCP_NODELAY`/keep-alive. Defaults are 2026.2.7's. Go differential `tests/differential/listen/run.sh`: 32/32 match.
- **Websocket regression from batch 4 fixed**: hop-by-hop stripping removed `Upgrade`, so every handshake reached Django as a plain GET (the embedded outpost's `HTTP error: 200 OK`; `/ws/client/` too). Ported `ReverseProxy`'s upgrade path as a byte splice. The embedded outpost now connects.
- HTTP differential (now with 11 upgrade cases): 504 cases, 496 equal / 8 nondeterministic / **0 different**; schema guard clean. Clippy clean.
- Upstream `ak-common`/`authentik` tests need nextest (one process per test) and a live PostgreSQL. Under plain `cargo test`, the env/tracing tests race, and the `db::`/session tests fail without a database. Each passes alone.

### Exact next action
Continue the M2 open items in `docs/COMPATIBILITY_REPORT.md`: `healthcheck worker` semantics and metrics on :9300 next. Owner decision needed: what the Rust embedded outpost reports for `golangVersion`, `openssl*` and `fipsEnabled` in its hello.

## Batch 4 — 2026-10-30

- Go front-server parity layer (`rust/src/server/go_compat/`): HTTP differential 484 equal / 9 nondeterministic / **0 different**; clippy clean; 9 parity unit tests.
- Fast loop: `scripts/rust-check.sh` (clippy/test in the exact build image). Format with `cargo +nightly fmt -p authentik -- --config-path rust/.cargo/rustfmt.toml`.
- Next: the M2 open items in `docs/COMPATIBILITY_REPORT.md`, starting with config listen-address compatibility and the embedded outpost websocket.

## Batch 3 — 2026-10-30

- **Re-pinned to authentik 2026.2.7** (`0936c5b0`), which production apps.mysoc.id runs. The reference stack was recreated, and every baseline re-extracted: schema fingerprint `a30d1060…`, 692 migrations, 1 113 API operations, 215 models, 66 actors.
- Password hashers re-verified at 2026.2.7 (152/65/31 + stored row): pass.
- 2026.2.7 has no upstream Rust; its front server is Go. Our Rust server (from 2026.8.5) now replaces the Go binary in the candidate image. Fixed: bare invocation means `server`; the version is reported as 2026.2.7.
- HTTP differential vs the Go server: all 440 cases differ, through 6 systematic front-server differences listed in `docs/COMPATIBILITY_REPORT.md`. The schema guard is clean on all databases.

### Exact next action
Fix differences 1→6 in `docs/COMPATIBILITY_REPORT.md` in order (Server header, gzip + Vary, health routing, robots.txt, static 404, Content-Length), porting from `internal/web/*.go` at 2026.2.7. Rerun `tests/differential/http/run.sh` after each, then do config listen-address compatibility.

## Batch 2 — 2026-10-30

- Decision R1: full Rust, no embedded CPython; expressions need a Rust Python-subset engine (M9b).
- Upstream Rust server vendored into `rust/` (byte-identical except the compat seam); our crates moved onto upstream's pinned workspace deps, with `ring` removed per upstream's FIPS `deny.toml`. Upstream lockfile versions are unchanged.
- Candidate image `candidate/Dockerfile` builds; 3-stack HTTP differential: 461 equal / 9 nondeterministic / 0 different; schema guard clean on all DBs.
- Not full Rust: Django still serves every request (see `docs/COMPATIBILITY_REPORT.md`).
- Deployment to apps.mysoc.id NOT done: production runs authentik **2026.2.7**, while this project targets 2026.8.5.


## Batch 1 — 2026-10-30

### Completed (all verified by commands that ran in this batch)

- Pinned upstream `version/2026.8.5` = `4ec0d19b98da3c329781894cd550da95d3033954` (`UPSTREAM.lock`, `scripts/bootstrap-upstream.sh`).
- Reference stack running from `reference/compose.yml` (authentik 2026.8.5 + PG 16, localhost-only ports 19000/19443/15432). It migrated cleanly: 777 migrations.
- Baselines: `baseline/schema/` (pg_dump, migration list, canonical JSON snapshot `8afc1fc8…`), `baseline/api/openapi.yml`, `baseline/inventory/` (live Django registry, OpenAPI operations, Go components).
- Audit docs `docs/*.md` (10 required documents) + generated `docs/FEATURE_MATRIX.md`.
- Rust workspace `rust/` (toolchain 1.97.1):
  - `ak-passwords`: verified equivalent to Django 5.2.17 hashers (see `docs/COMPATIBILITY_REPORT.md`).
  - `ak-schema-guard`: snapshot/verify/diff, verified against a restored copy and injected drift.
- `cargo test --workspace` 17 passed; `cargo clippy --workspace --all-targets` 0 warnings; `cargo fmt --check` clean.

### Blockers (need the project owner)

- R1 Python expressions: keep embedded CPython as the sandbox, or not? (`docs/MIGRATION_PLAN.md`)
- R2 Enterprise license: confirm subscription/agreement, or exclude EE.

### Exact next action (M2)

1. Vendor `upstream/src/` (MIT, keep attribution in `NOTICE.md`) into `rust/apps/server`, using `packages/ak-common` and `ak-axum` via path dependencies on `../upstream/packages/*`.
2. Insert an (initially empty) compat router before `fallback(forward_request)` in the vendored `core.rs`.
3. Build a candidate image from the upstream Dockerfile with our binary swapped in, and run it beside the reference on a snapshot copy.
4. Start M3: HTTP differential harness. Its first run must show 0 differences, since everything still falls back to Django, and must detect a seeded difference.

### How to resume

```bash
./scripts/bootstrap-upstream.sh
docker compose -f reference/compose.yml --env-file reference/.env up -d   # .env is local-only; recreate with fresh random values if missing
./tests/differential/passwords/run.sh
```
