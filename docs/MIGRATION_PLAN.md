# Migration plan

Dependency-ordered backlog. Each milestone has acceptance criteria; a feature moves to **Verified equivalent** only when its criteria pass against the pinned reference.

## Honest scope

The upstream behavior to reproduce is about 91k lines of Python core, 12k of Go and 1 193 REST operations, plus the protocol stacks. Upstream's 68k lines of Python tests set the verification bar. This is a multi-person, multi-month program, not a single session. Work proceeds in bounded batches, each ending with a checkpoint (`CHECKPOINT.md`).

## Milestones

| # | Milestone | Depends on | Acceptance criteria | State |
| --- | --- | --- | --- | --- |
| M0 | Baseline: pin, reference stack, schema/API/inventory baselines, audit docs | — | Reference boots; baselines committed; guard verifies reference | **Done** (2026-10-30) |
| M1 | Password hashers | M0 | Byte-identical encodings; verify_password parity incl. errors; both-direction interop; real row | **Done** |
| M2 | Rust front server replacing 2026.2.7's Go `cmd/server` (vendored from upstream 2026.8.5), compat router (empty list) | M0 | Candidate image passes the 2026.2.7 health checks; the HTTP differential against the **Go** server shows 0 different; schema guard clean | In progress: 6 systematic differences open |
| M3 | Differential harness: replay engine, normalizers, DB state diff, CI job | M2 | Harness detects a seeded difference; runs the reference and candidate stacks in parallel from equal snapshots | Next |
| M4 | Core read models (`ak-models`): User, Group, Application, Provider/Source MTI, Token, Brand, Tenant | M2 | Rust decodes every row of a populated reference DB; round-trip writes leave the rows byte-equal | |
| M5 | Sessions + authentication middleware (session cookie, token auth, CSRF, tenant/brand resolution) | M1, M4 | Cookie/session differential incl. expiry, logout, concurrent login | |
| M6 | RBAC + guardian permissions | M4, M5 | Permission matrix differential for all models × roles | |
| M7 | Read-only API endpoints (`core`, `rbac`, `crypto`, `events` list/retrieve) | M5, M6 | Per-operation differential incl. filtering, ordering, search, pagination, 401/403/404 | |
| M8 | Write API endpoints + signals/side effects (events, cache invalidation) | M7 | State-transition differential (rows + emitted events) | |
| M9 | Policy engine (non-expression policies), flow planner and executor, core stages (identification, password, user_login/logout/write, prompt, consent, deny, redirect) | M5–M8 | e2e login/enroll/recovery flows identical (`tests/e2e/test_flows_*`) | |
| M10 | Authenticator stages (TOTP, static, WebAuthn, email, SMS, Duo, validate) | M9 | `test_flows_authenticators*` pass; WebAuthn vectors | |
| M11 | OAuth2/OIDC provider | M9 | OIDF conformance suite pass on both; token/claim differential | |
| M12 | SAML provider, sources (OAuth, SAML, LDAP, SCIM, Plex, Telegram, Kerberos) | M9 | Corresponding e2e suites | |
| M13 | Tasks/worker: 70 actors on the Postgres broker (`authentik_tasks_*`), schedules | M8 | Per-actor state differential; retries; schedule triggers | |
| M14 | Blueprints engine + bundled blueprints | M8 | Applying every bundled blueprint yields identical DB state | |
| M15 | Outposts: controller/API/websocket; LDAP, RADIUS, RAC in Rust; proxy re-verified | M11, M13 | `test_provider_{ldap,radius,rac,proxy*}` | |
| M9b | Rust Python-subset expression engine + context API (decision R1) | M4 | Corpus differential: every corpus expression returns or raises identically | |
| M16 | Remaining apps (admin, endpoints, recovery, tenants API, …) | all | Feature matrix 100 % of non-blocked rows verified | |
| M17 | Remove adapters (Django fallback, pyo3, Python worker); hardening, fuzzing, benchmarks, release | all | No Python in the image; full suites green; rollback drill | |

## Risks and decisions needing the project owner

- **R1 — Expression policies and property mappings are user-written Python. DECIDED 2026-10-30: full Rust, no embedded CPython** (owner: "ubah total ke rust"). `authentik/lib/expression` evaluates Python source stored in the database, with authentik-specific context objects, for `ExpressionPolicy`, every `PropertyMapping` type (OAuth scopes, SAML, LDAP, SCIM, RADIUS, …), prompt fields, and blueprints `!Context`/`!Format`. Consequence: the project must ship a Rust interpreter for the Python subset these expressions use, plus authentik's expression context API (`request`, `user`, `ak_*` helpers, `regex_*`, `ak_create_event`, …). Required follow-up work:
  1. Corpus: collect every expression shipped in `blueprints/` and upstream tests, plus the documented helpers, to define the supported subset.
  2. A differential test that evaluates each corpus expression in the reference (`ExpressionEvaluator`) and in Rust and compares results and raised exceptions.
  3. Expressions outside the supported subset must fail loudly, logging an event like upstream's evaluation errors. They must never silently return a value.

  Until this exists, every feature that evaluates expressions stops at **Implemented, unverified**. Existing databases whose expressions use Python beyond the subset are a known compatibility risk that must be reported per deployment.
- **R2 — Enterprise code (`authentik/enterprise/`, 12 930 lines, 20 apps).** Under the EE license a Rust port is a modification owned by Authentik Security Inc., usable only with a valid subscription and not distributable. All EE rows are **Blocked with documented evidence** until the owner confirms a subscription/agreement, or decides to exclude them.
- **R3 — Shared database during transition.** Python and Rust write the same rows. Every model port must prove round-trip byte equality (M4) before any Rust write path is enabled.
- **R4 — Kerberos** needs MIT krb5 bindings. Pure-Rust options are limited, so this may require FFI.
