# Checkpoint

Durable resume point for the authentik → Rust rewrite. Update at the end of every batch.

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
