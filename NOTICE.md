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
| `rust/src/**` (except the lines marked `authentik-rs`; the files that are not upstream, `src/server/compat.rs`, `src/server/go_compat/` and `src/metrics/go_text.rs`; `src/healthcheck.rs`, now a port of 2026.2.7's Go `cmd/server/healthcheck.go`; and `src/brands/tls.rs` and `src/server/tls.rs`, now ports of Go's `internal/web/brand_tls`, `web_tls.go` and `internal/outpost/ak` `CryptoStore`) | `src/` at 2026.8.5 `4ec0d19b` (MIT). The compatibility target is 2026.2.7, which has no Rust; this server replaces 2026.2.7's Go `cmd/server`. |
| `rust/packages/ak-axum`, `ak-common`, `client-rust` (except the lines marked `authentik-rs`, plus `ak-axum/src/accept/go_tcp.rs` and `ak-axum/testdata/`, which are not upstream) | `packages/*` at `4ec0d19b` (MIT); `client-rust` is generated from `schema.yml` |
| `rust/build.rs`, `rust/.cargo/*`, `rust/rust-toolchain.toml`, `rust/LICENSE`, `rust/authentik/lib/default.yml` (except the `listen` addresses marked `authentik-rs`, which are 2026.2.7's), `rust/web/robots.txt`, `rust/web/security.txt` | same paths at `4ec0d19b` (MIT) |
| `rust/Cargo.toml` | root `Cargo.toml` at `4ec0d19b` (MIT), with the members list and an "authentik-rs additions" block changed |
| `rust/web/dist/standalone/loading/startup.html` | build output copied from `ghcr.io/goauthentik/server:2026.8.5` (client-side, MIT) |
| `baseline/api/openapi.yml` | `schema.yml` at 2026.2.7 `0936c5b0` (MIT) |
| `reference/compose.yml` | `lifecycle/container/compose.yml` at 2026.2.7 `0936c5b0` (MIT), with ports bound to 127.0.0.1, the Docker socket mount removed and a PG port added |
