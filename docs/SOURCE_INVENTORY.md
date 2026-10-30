# Source inventory

## Pinned compatibility target

| Item | Value |
| --- | --- |
| Repository | https://github.com/goauthentik/authentik |
| Tag | `version/2026.8.5` (latest stable on 2026-10-30; `main` was at `7905cc43`) |
| Commit | `4ec0d19b98da3c329781894cd550da95d3033954` (2026-10-21) |
| Reference image | `ghcr.io/goauthentik/server:2026.8.5` |
| Database | PostgreSQL 16 (`postgres:16-alpine`, reports 16.15) |
| Python / Django | Python 3.14.7 (fips-python base image), Django 5.2.17 |
| Rust toolchain | 1.97.1 (upstream `rust-toolchain.toml`) |
| OpenAPI | `schema.yml`, OpenAPI 3, info.version `2026.8.5`, sha256 `1ffe03e3…1505cfe` (copy in `baseline/api/openapi.yml`) |

`UPSTREAM.lock` holds these values; `scripts/bootstrap-upstream.sh` recreates and checks the pinned checkout in `upstream/` (gitignored).

## Size (measured)

| Area | Measure |
| --- | --- |
| Python core (`authentik/`, `lifecycle/`, `packages/django-*`), excluding tests and migrations | 91 405 lines |
| Python tests | 67 610 lines in 351 test files |
| Django migrations | 646 files; 777 applied migration rows in the reference DB |
| Go (`cmd/`, `internal/`, excluding tests) | 11 720 lines |
| Existing upstream Rust (`src/`, `packages/ak-axum`, `packages/ak-common`) | 14 337 lines |
| Web UI TypeScript (`web/src`) | 115 887 lines |
| Django apps (live registry) | 104 installed, 85 tenant apps, 2 schemas (`public`, `template`) |
| Models (live registry, incl. auto-created through tables) | 233 |
| URL patterns (live resolver) | 689 (609 under `api/`, 80 others) |
| Background actors (dramatiq, live broker) | 70, all on queue `default` |
| REST operations (OpenAPI) | 1 193 across 27 tags, 925 component schemas |
| Database objects (pg_catalog snapshot) | 4 113 (291 relations, 1 387 columns, 756 constraints, 827 indexes, 60 sequences, 6 functions, 5 triggers, 1 view) |

Machine-readable sources: `baseline/inventory/django.json` (extracted live by `scripts/extract_django_inventory.py`), `baseline/inventory/openapi_operations.json`, `baseline/inventory/go_components.json`, `baseline/schema/reference-schema.json`.

## Repository map

| Path | Language | Role at 2026.8.5 |
| --- | --- | --- |
| `authentik/` | Python | Django core: the IdP. Source of truth for behavior. |
| `lifecycle/` | Python/bash | Boot: `ak` entrypoint, migrations (`migrate.py`, `system_migrations/`), gunicorn config, worker process. |
| `src/` | Rust | **Already Rust upstream.** The `authentik` binary: front HTTP server (`src/server`), worker supervisor (`src/worker`), metrics, health check, embedded Rust **proxy outpost** (`src/outpost/proxy`). Embeds Python via pyo3 and spawns gunicorn on a unix socket; every non-static request goes through `fallback(forward_request)` to Django (`src/server/core.rs`). |
| `packages/ak-axum`, `packages/ak-common` | Rust | Shared crates: axum server/accept/extract (client IP, trusted proxy, PROXY protocol, TLS), config loader, DB pool, tracing, arbiter (lifecycle). |
| `packages/client-rust`, `client-go`, `client-ts` | generated | API clients generated from `schema.yml`. |
| `packages/django-channels-postgres`, `django-dramatiq-postgres`, `django-postgres-cache` | Python | Postgres-backed channels layer, task broker and cache (tables `django_channels_postgres_*`, `authentik_tasks_*`, cache table). |
| `cmd/ldap`, `cmd/radius`, `cmd/rac` + `internal/outpost/*` | Go | LDAP, RADIUS, RAC outposts (still Go; built by `lifecycle/container/{ldap,radius,rac}.Dockerfile`). |
| `cmd/proxy`, `internal/outpost/proxyv2` | Go | Legacy Go proxy outpost; the shipped proxy image now builds the Rust `proxy` feature (`proxy.Dockerfile`). |
| `cmd/server`, `internal/web`, `internal/gounicorn` | Go | Legacy Go front server, superseded by `src/server` in the shipped image (`Dockerfile` builds only the Rust `authentik` binary). |
| `web/` | TypeScript (Lit + PatternFly) | Admin, user and flow UIs. Retained unchanged. |
| `blueprints/` | YAML | `default/` (19), `system/` (11), `example/` (13), `migrations/` (1), `testing/` (1). |
| `schemas/` | XSD/JSON | SAML, WS-*, SCIM schemas used at runtime. |
| `tests/e2e`, `tests/openid_conformance`, `tests/integration` | Python | Selenium e2e flows/providers/sources, OIDF conformance suite driver. |
| `website/` | Docusaurus | Docs (CC BY-SA 4.0). Not part of the runtime. |

## Runtime topology (reference)

```
client ─► authentik server (Rust, src/server)
            ├─ /-/health/*            Rust
            ├─ static (/static, web/dist)   Rust
            ├─ embedded proxy outpost  Rust
            └─ everything else ─► gunicorn (unix socket) ─► Django (ASGI/WSGI)
authentik worker (Rust supervisor) ─► Python dramatiq workers (Postgres broker)
outposts: ldap / radius / rac (Go), proxy (Rust)
PostgreSQL 16 (only external dependency; no Redis since the Postgres-backed broker/cache/channels)
```

## Licenses

| Scope | License |
| --- | --- |
| Everything outside the directories below | MIT (`LICENSE`, © 2023 Jens Langhammer) |
| `authentik/enterprise/` | authentik Enterprise Edition license (`authentik/enterprise/LICENSE`). Copy/modify allowed for development and testing; production use and any use of modifications require a valid EE subscription; modifications belong to Authentik Security Inc.; distribution forbidden. |
| Client-side JavaScript | MIT (Expat) |
| `website/` | CC BY-SA 4.0 |
| Third-party components | their own licenses |

Provenance: every Rust module ported from upstream must name its upstream source in its module docs. `NOTICE.md` lists reused upstream code.

## Upstream agent instructions

`AGENTS.md`/`CLAUDE.md` were read. Relevant constraints carried over: product name is lowercase `authentik`; `schema.yml` and `packages/client-*` are generated, never hand-edited; the Makefile is the command hub (`make test`, `make rust-test`, `make go-test`).
