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
| `baseline/api/openapi.yml` | `schema.yml` at `4ec0d19b` (MIT) |
| `reference/compose.yml` | `lifecycle/container/compose.yml` at `4ec0d19b` (MIT), with ports bound to 127.0.0.1, the Docker socket mount removed and a PG port added |
