# Architecture

## Principle: strangler fig on the existing Rust front server

authentik 2026.8.5 already runs a Rust front server (`upstream/src/server`). It terminates HTTP/TLS, serves health and static files and the embedded proxy outpost, and forwards everything else to gunicorn/Django through a single `fallback(forward_request)` (`src/server/core.rs`). That fallback is the migration seam:

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
| `ak-models` (next) | Row types for authentik tables, decoded exactly as Django stores them (UUIDs, JSONB, timestamptz, MTI parent/child) | Planned |
| `ak-server` (next) | Upstream `src/` server/worker vendored with attribution, plus the compat router | Planned |
| `ak-sessions`, `ak-auth`, `ak-rbac`, `ak-flows`, `ak-policies`, `ak-stages-*`, `ak-providers-*`, `ak-sources-*`, `ak-events`, `ak-tasks`, `ak-blueprints`, `ak-tenants`, `ak-outposts` | Domain ports, in dependency order | Planned |

Shared infrastructure is reused from upstream rather than rewritten: `packages/ak-common` (config loader that already reproduces `AUTHENTIK_*` env/file semantics, DB pool, tracing, arbiter) and `packages/ak-axum` (accept/extract layers). The plan is to depend on them by path from the pinned checkout.

## Technology choices (and why)

- **axum/tokio/hyper/rustls/sqlx**: what upstream already uses (`Cargo.toml` pins). Same stack, fewer integration surprises.
- **RustCrypto (pbkdf2, argon2, scrypt, sha2) and the `bcrypt` crate**: pyca/bcrypt 5 is a thin wrapper over the same `bcrypt` crate, so the bcrypt behavior matches by construction. Differential tests confirmed every hasher.
- **sqlx with runtime-checked queries**: queries are written against the immutable schema. Compile-time `query!` checking against a baseline database is planned for model crates.
- No ORM migrations, ever. The Rust side holds no migration files. `ak-schema-guard verify` runs before and after every candidate test run.

## Deployment contract

Same container entrypoints (`server`, `worker`, `allinone`, `healthcheck`), same ports (9000/9443, metrics 9300), same `AUTHENTIK_*` variables, and the same volumes (`/data`, `/certs`, `/templates`). The reference compose file in `reference/compose.yml` is the deployment baseline.
