# API contract

## REST API (`/api/v3/`)

The contract is the pinned `schema.yml` (copied to `baseline/api/openapi.yml`, sha256 `1ffe03e3650de36497946fcc2229d0d913ac46fc49236583b0bbf15f91505cfe`). Generated clients in `packages/client-{go,rust,ts}` must keep working unmodified, so the Rust implementation serves exactly this schema.

Operation list: `baseline/inventory/openapi_operations.json` (method, path, operationId, tags, security, response codes).

| Tag | Operations | | Tag | Operations |
| --- | ---: | --- | --- | ---: |
| stages | 210 | | rbac | 22 |
| sources | 173 | | admin | 14 |
| providers | 131 | | lifecycle (EE) | 14 |
| propertymappings | 111 | | tenants | 14 |
| authenticators | 83 | | rac | 13 |
| core | 78 | | oauth2 | 12 |
| policies | 76 | | crypto | 10 |
| endpoints | 70 | | enterprise (EE) | 10 |
| outposts | 34 | | managed | 10 |
| events | 33 | | tasks | 10 |
| requests (EE) | 29 | | agents (EE) | 6 |
| flows | 22 | | reports (EE) | 3 |
| | | | ssf (EE) | 3 |
| | | | root, schema | 1 + 1 |
| **Total** | | | | **1 193** |

Security schemes: `authentik` (Bearer token / session), `authentik_device_auth`, `authentik_device_enroll`, `authentik_device_federation`.

Cross-cutting DRF behavior that every Rust endpoint must reproduce (from `settings.REST_FRAMEWORK`, recorded in `baseline/inventory/django.json`): pagination envelope (`pagination` object + `results`, `page`/`page_size` query params), `ordering`/`search`/django-filter query parameters, validation error shape (`{field: [messages]}` and `non_field_errors`), 403 vs 401 selection by authenticator, `ETag`/`Cache-Control` where set, CSRF enforcement for session-authenticated unsafe methods, and the JSON renderer/parser settings.

## Non-API HTTP surface (80 URL patterns)

From the live resolver (`baseline/inventory/django.json`, `urls[]` not under `api/`):

| Prefix | Routes | Examples |
| --- | ---: | --- |
| `application/` | 30 | OAuth2/OIDC authorize, token, userinfo, introspection, revocation, end-session, JWKS; SAML SSO/SLO/metadata; proxy/RAC endpoints |
| `source/` | 19 | OAuth/SAML/Plex/Telegram/Kerberos source redirect + callback, SCIM source endpoints |
| `.well-known/` | 4 | OIDC discovery, WebFinger |
| `if/` | 4 | Admin / user / flow interface shells (HTML templates hosting the web UI) |
| `flows/` | 4 | Flow executor, flow inspector, cancel |
| `endpoints/`, `endpoint/`, `device` | 7 | device/endpoint flows |
| `ws/` | 2 | WebSockets (outpost control channel, client) via channels |
| `-/` | 3 | health, metrics |
| others | 7 | root redirect, `login`, `user`, `setup`, `recovery` |

## Middleware chain (order matters)

`PrometheusBefore → DefaultTenant → Logging → ClientIP → BoundSession → Locale → Authentication → RequestID → Brand → EnterpriseAudit → Security → Common → CsrfView (authentik) → Messages → XFrameOptions → Impersonate → InitialPermissions → Enterprise → PrometheusAfter`.

Authentication backends: `InbuiltBackend`, `TokenBackend`, `LDAPBackend`, guardian `ObjectPermissionBackend`.

## Verification approach

The differential harness (`TEST_STRATEGY.md`) replays the same request against the reference and the candidate, compares status, headers (normalized for `Date`, request IDs, `Set-Cookie` values with checked invariants), and the JSON body after normalizing only generated identifiers and timestamps. An endpoint is complete only when its operation(s) pass for success and failure cases and the schema guard reports no drift.

Status today: no API endpoint has been ported. The candidate server still forwards every API request to Django.
