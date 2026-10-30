# API contract

## REST API (`/api/v3/`)

The contract is the pinned `schema.yml` (copied to `baseline/api/openapi.yml`, sha256 `91a195e4695d4149c1824d10af6b02c6f1492974a63bec4fd9e2b9fa9aca8207`, authentik 2026.2.7). Generated clients in `packages/client-{go,rust,ts}` must keep working unmodified, so the Rust implementation serves exactly this schema.

Operation list: `baseline/inventory/openapi_operations.json` (method, path, operationId, tags, security, response codes).

| Tag | Operations |
| --- | ---: |
| stages | 202 |
| sources | 173 |
| providers | 125 |
| propertymappings | 111 |
| authenticators | 83 |
| policies | 76 |
| core | 67 |
| endpoints | 56 |
| outposts | 34 |
| events | 32 |
| flows | 23 |
| rbac | 22 |
| admin | 14 |
| tenants | 14 |
| rac | 13 |
| oauth2 | 12 |
| crypto | 10 |
| enterprise (EE) | 10 |
| lifecycle (EE) | 10 |
| tasks | 10 |
| managed | 9 |
| reports (EE) | 3 |
| ssf (EE) | 2 |
| root | 1 |
| schema | 1 |
| **Total** | **1113** |

Security schemes: `authentik` (Bearer token / session), `authentik_device_auth`, `authentik_device_enroll`, `authentik_device_federation`.

Cross-cutting DRF behavior that every Rust endpoint must reproduce (from `settings.REST_FRAMEWORK`, recorded in `baseline/inventory/django.json`): pagination envelope (`pagination` object + `results`, `page`/`page_size` query params), `ordering`/`search`/django-filter query parameters, validation error shape (`{field: [messages]}` and `non_field_errors`), 403 vs 401 selection by authenticator, `ETag`/`Cache-Control` where set, CSRF enforcement for session-authenticated unsafe methods, and the JSON renderer/parser settings.

## Non-API HTTP surface (71 URL patterns)

From the live resolver (`baseline/inventory/django.json`, `urls[]` not under `api/`):

| Prefix | Routes | Examples |
| --- | ---: | --- |
| `application/` | 22 | OAuth2/OIDC authorize, token, userinfo, introspection, revocation, end-session, JWKS; SAML SSO/SLO/metadata; proxy/RAC endpoints |
| `source/` | 19 | OAuth/SAML/Plex/Telegram/Kerberos source redirect + callback, SCIM source endpoints |
| `.well-known/` | 4 | OIDC discovery, WebFinger |
| `if/` | 4 | Admin / user / flow interface shells (HTML templates hosting the web UI) |
| `flows/` | 4 | Flow executor, flow inspector, cancel |
| `endpoints/`, `endpoint/`, `device`, `policy` | 7 | device/endpoint flows, policy binding views |
| `ws/` | 2 | WebSockets (outpost control channel, client) via channels |
| `-/` | 3 | health, metrics |
| others | 7 | root redirect, `login`, `user`, `setup`, `recovery` |

## Middleware chain (order matters)

`PrometheusBefore → DefaultTenant → Logging → ClientIP → BoundSession → Locale → Authentication → RequestID → Brand → EnterpriseAudit → Security → Common → CsrfView (authentik) → Messages → XFrameOptions → Impersonate → InitialPermissions → Enterprise → PrometheusAfter`.

Authentication backends: `InbuiltBackend`, `TokenBackend`, `LDAPBackend`, guardian `ObjectPermissionBackend`.

## Verification approach

The differential harness (`TEST_STRATEGY.md`) replays the same request against the reference and the candidate, compares status, headers (normalized for `Date`, request IDs, `Set-Cookie` values with checked invariants), and the JSON body after normalizing only generated identifiers and timestamps. An endpoint is complete only when its operation(s) pass for success and failure cases and the schema guard reports no drift.

Status today: no API endpoint has been ported. The candidate server still forwards every API request to Django.

At 2026.2.7 the Go front server owns part of the HTTP surface itself. It must be matched exactly by the Rust server: `/-/health/live/`, `/-/health/ready/`, `/static/dist/`, `/static/authentik/`, `/if/{flow,admin,user,rac}/…/assets`, `/files/media/`, `/files/reports/`, `/robots.txt`, `/.well-known/security.txt`, the `/` redirect when `web.path` is not `/`, metrics on `:9300`, brand TLS on `:9443`, and the embedded proxy outpost.
