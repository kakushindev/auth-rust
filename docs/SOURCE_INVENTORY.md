# Source inventory

## Pinned compatibility target

| Item | Value |
| --- | --- |
| Repository | https://github.com/goauthentik/authentik |
| Tag | `version/2026.2.7`, chosen because it is what production `apps.mysoc.id` runs (`omb-ipb-2026/infrastructure/apps/mysoc/authentik/release.yaml`). Latest stable on 2026-10-30 was 2026.8.5. |
| Commit | `0936c5b0ce31dc98f5f9eb4b06730a13f6da0333` (2026-09-09) |
| Reference image | `ghcr.io/goauthentik/server:2026.2.7` |
| Database | PostgreSQL 16 (`postgres:16-alpine`, reports 16.15) |
| Python / Django | Python 3.14.5 (fips-python base image), Django 5.2.17, argon2-cffi 25.1.0, bcrypt 5.0.0 |
| Rust toolchain | 1.97.1, taken from 2026.8.5 together with the Rust server sources. 2026.2.7 ships **no Rust**. |
| OpenAPI | `schema.yml`, OpenAPI 3, info.version `2026.2.7`, sha256 `91a195e4…aca8207` (copy in `baseline/api/openapi.yml`) |

`UPSTREAM.lock` holds these values; `scripts/bootstrap-upstream.sh` recreates and checks the pinned checkout in `upstream/` (gitignored).

## Size (measured)

| Area | Measure |
| --- | --- |
| Python core (`authentik/`, `lifecycle/`, `packages/`), excluding tests and migrations | 81 256 lines (of which `authentik/enterprise/` 9 131) |
| Python tests | 50 672 lines |
| Django migrations | 557 files; 692 applied migration rows in the reference DB |
| Go (`cmd/`, `internal/`, excluding tests) | 11 636 lines, including the **front server** (`cmd/server`, `internal/web`, `internal/gounicorn`) |
| Upstream Rust | none at 2026.2.7. Our `rust/src` + `packages/ak-*` come from 2026.8.5, where upstream had replaced the Go server with Rust. |
| Web UI TypeScript (`web/src`) | 96 237 lines |
| Django apps (live registry) | 101 installed, 82 tenant apps, 2 schemas (`public`, `template`) |
| Models (live registry, incl. auto-created through tables) | 215 |
| URL patterns (live resolver) | 641 (570 under `api/`, 71 others) |
| Background actors (dramatiq, live broker) | 66 |
| REST operations (OpenAPI) | 1 113 across 25 tags |
| Database objects (pg_catalog snapshot) | 3 693 (271 relations, 1 234 columns, 678 constraints, 745 indexes, 58 sequences, 6 functions, 5 triggers, 1 view) |

Machine-readable sources: `baseline/inventory/django.json` (extracted live by `scripts/extract_django_inventory.py`), `baseline/inventory/openapi_operations.json`, `baseline/inventory/go_components.json`, `baseline/schema/reference-schema.json`.

## Repository map

| Path | Language | Role at 2026.2.7 |
| --- | --- | --- |
| `authentik/` | Python | Django core: the IdP. Source of truth for behavior. |
| `lifecycle/` | Python/bash | Boot: `ak` entrypoint, migrations (`migrate.py`, `system_migrations/`), gunicorn config, worker process. |
| `cmd/server`, `internal/web`, `internal/gounicorn` | Go | **Front server at 2026.2.7.** The `authentik` binary terminates HTTP/TLS, serves static files, `/-/health/*` and metrics, embeds the Go proxy outpost, supervises gunicorn on a unix socket and reverse-proxies everything else to Django. This is the component our Rust server must reproduce first. |
| `packages/client-rust`, `client-go`, `client-ts` | generated | API clients generated from `schema.yml`. |
| `packages/django-channels-postgres`, `django-dramatiq-postgres`, `django-postgres-cache` | Python | Postgres-backed channels layer, task broker and cache (tables `django_channels_postgres_*`, `authentik_tasks_*`, cache table). |
| `cmd/ldap`, `cmd/radius`, `cmd/rac` + `internal/outpost/*` | Go | LDAP, RADIUS, RAC outposts (still Go; built by `lifecycle/container/{ldap,radius,rac}.Dockerfile`). |
| `cmd/proxy`, `internal/outpost/proxyv2` | Go | Proxy outpost (standalone and embedded in the server). |
| `web/` | TypeScript (Lit + PatternFly) | Admin, user and flow UIs. Retained unchanged. |
| `blueprints/` | YAML | `default/` (19), `system/` (11), `example/` (13), `migrations/` (1), `testing/` (1). |
| `schemas/` | XSD/JSON | SAML, WS-*, SCIM schemas used at runtime. |
| `tests/e2e`, `tests/openid_conformance`, `tests/integration` | Python | Selenium e2e flows/providers/sources, OIDF conformance suite driver. |
| `website/` | Docusaurus | Docs (CC BY-SA 4.0). Not part of the runtime. |

## Runtime topology (reference)

```
client ─► authentik server (Go, cmd/server)
            ├─ /-/health/*, metrics :9300      Go
            ├─ static (/static, web/dist)      Go
            ├─ embedded proxy outpost          Go
            └─ everything else ─► gunicorn (unix socket) ─► Django (ASGI)
authentik worker: `python -m manage worker` (dramatiq, Postgres broker)
outposts: ldap / radius / rac / proxy (Go)
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
