# Architecture

## Principle: strangler fig on the existing Rust front server

The compatibility target is authentik 2026.2.7, whose front server is the Go `authentik` binary (`cmd/server`). It terminates HTTP/TLS, serves health checks, static files and metrics, embeds the Go proxy outpost, and reverse-proxies everything else to gunicorn/Django. Upstream later replaced it with a Rust server (`src/server` in 2026.8.x). We vendor that Rust server and make it behave exactly like the 2026.2.7 Go server (M2). Its single `fallback(forward_request)` to gunicorn is the migration seam:

```
request ─► Rust server (vendored from upstream src/server)
             ├─ /-/health, static, proxy outpost        (already Rust upstream)
             ├─ compat router: routes ported to Rust    (this project)
             │     enabled per route by a compiled-in list of routes whose
             │     differential suite passed (no runtime flag that can widen it)
             └─ fallback ─► gunicorn ─► Django          (temporary adapter, tracked)
```

- A route moves to Rust only after its differential tests pass. Until then Django serves it, so the product stays complete at every step. No placeholder handlers exist.
- Both implementations share one PostgreSQL database and one schema, so the same rows are read and written by Python and Rust during the transition. This forces exact data-format compatibility (verified per model) and makes rollback immediate: drop the route from the list.
- The Django fallback, the pyo3 embedding and the Python worker are **temporary compatibility adapters**. They are listed in `COMPATIBILITY_REPORT.md` and must be gone at the full-Rust milestone.

## Workspace (`rust/`)

| Crate | Purpose | State |
| --- | --- | --- |
| `ak-passwords` | Django password hashers (`django.contrib.auth.hashers`) | Done, verified against reference |
| `ak-schema-guard` | Schema snapshot/verify (release gate) | Done, verified (restore + drift tests) |
| `ak-models` | Row types for authentik tables, decoded exactly as Django stores them (UUIDs, JSONB, timestamptz, MTI parent/child) | Done (M4) |
| server (`rust/src/`) | Upstream server/worker vendored with attribution, plus the compat router (`PORTED_ROUTES`) | Done (M2), routes added per milestone |
| `ak-pickle` | Safe pickle reader, and a writer byte-identical to CPython 3.14's protocol 5 for the graphs authentik stores | Done (M5, M8) |
| `ak-geoip` | MaxMind DB reader and `geoip2` models | Done (M5) |
| `ak-auth` | Request identity: host, brand, tenant, client IP, tokens, sessions, bindings, CSRF, response cookies | Done (M5) |
| `ak-rbac` | Role-based permissions through `ak-guardian` | Done (M6) |
| `ak-api` | The read API (15 viewsets) and session-cookie handling | Done (M7), M8 in progress |
| `ak-events` | Write-side side effects: dramatiq tasks on the Postgres broker, events | In progress (M8) |
| `ak-flows`, `ak-policies`, `ak-stages-*`, `ak-providers-*`, `ak-sources-*`, `ak-blueprints`, `ak-tenants`, `ak-outposts` | Domain ports, in dependency order | Planned |

Shared infrastructure is reused from upstream rather than rewritten: `packages/ak-common` (config loader that already reproduces `AUTHENTIK_*` env/file semantics, DB pool, tracing, arbiter) and `packages/ak-axum` (accept/extract layers). The plan is to depend on them by path from the pinned checkout.

## Technology choices (and why)

- **axum/tokio/hyper/rustls/sqlx**: what upstream already uses (`Cargo.toml` pins). Same stack, fewer integration surprises.
- **RustCrypto (pbkdf2, argon2, scrypt, sha2) and the `bcrypt` crate**: pyca/bcrypt 5 is a thin wrapper over the same `bcrypt` crate, so the bcrypt behavior matches by construction. Differential tests confirmed every hasher.
- **sqlx with runtime-checked queries**: queries are written against the immutable schema. Compile-time `query!` checking against a baseline database is planned for model crates.
- No ORM migrations, ever. The Rust side holds no migration files. `ak-schema-guard verify` runs before and after every candidate test run.

## Deployment contract

Same container entrypoints (`server`, `worker`, `allinone`, `healthcheck`), same ports (9000/9443, metrics 9300), same `AUTHENTIK_*` variables, and the same volumes (`/data`, `/certs`, `/templates`). The reference compose file in `reference/compose.yml` is the deployment baseline.
