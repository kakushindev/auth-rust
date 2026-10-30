# Notices and provenance

This project reimplements authentik (https://github.com/goauthentik/authentik).

authentik is Copyright (c) 2023 Jens Langhammer and licensed under the MIT license, except `authentik/enterprise/` (authentik Enterprise Edition license, Copyright (c) 2022-present Authentik Security Inc.) and `website/` (CC BY-SA 4.0). No code from `authentik/enterprise/` has been ported.

## Behavior reimplemented (no code copied)

| Rust module | Upstream behavior it reproduces | Upstream license |
| --- | --- | --- |
| `rust/crates/ak-passwords` | `django.contrib.auth.hashers` (Django 5.2.17, BSD-3-Clause) as configured by authentik; argon2-cffi and pyca/bcrypt behavior | Django: BSD-3-Clause; argon2-cffi: MIT; pyca/bcrypt: Apache-2.0 |

## Upstream files copied verbatim

| File | Source |
| --- | --- |
| `rust/src/**` (except `src/server/compat.rs`, and 2 marked lines in `src/server/core.rs`, `src/server/mod.rs`) | `src/` at `4ec0d19b` (MIT) |
| `rust/packages/ak-axum`, `ak-common`, `client-rust` | `packages/*` at `4ec0d19b` (MIT); `client-rust` is generated from `schema.yml` |
| `rust/build.rs`, `rust/.cargo/*`, `rust/rust-toolchain.toml`, `rust/LICENSE`, `rust/authentik/lib/default.yml`, `rust/web/robots.txt`, `rust/web/security.txt` | same paths at `4ec0d19b` (MIT) |
| `rust/Cargo.toml` | root `Cargo.toml` at `4ec0d19b` (MIT), with the members list and an "authentik-rs additions" block changed |
| `rust/web/dist/standalone/loading/startup.html` | build output copied from `ghcr.io/goauthentik/server:2026.8.5` (client-side, MIT) |
| `baseline/api/openapi.yml` | `schema.yml` at `4ec0d19b` (MIT) |
| `reference/compose.yml` | `lifecycle/container/compose.yml` at `4ec0d19b` (MIT), with ports bound to 127.0.0.1, the Docker socket mount removed and a PG port added |
