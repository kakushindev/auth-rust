# Migration plan

Dependency-ordered backlog. Each milestone has acceptance criteria; a feature moves to **Verified equivalent** only when its criteria pass against the pinned reference.

## Honest scope

The upstream behavior to reproduce is about 91k lines of Python core, 12k of Go and 1 193 REST operations, plus the protocol stacks. Upstream's 68k lines of Python tests set the verification bar. This is a multi-person, multi-month program, not a single session. Work proceeds in bounded batches, each ending with a checkpoint (`CHECKPOINT.md`).

## Milestones

| # | Milestone | Depends on | Acceptance criteria | State |
| --- | --- | --- | --- | --- |
| M0 | Baseline: pin, reference stack, schema/API/inventory baselines, audit docs | — | Reference boots; baselines committed; guard verifies reference | **Done** (2026-10-30) |
| M1 | Password hashers | M0 | Byte-identical encodings; verify_password parity incl. errors; both-direction interop; real row | **Done** |
| M2 | Vendor upstream `src/` server/worker into `rust/`, build our `authentik` binary, add compat router (empty list) | M0 | Candidate image passes upstream health checks; full API differential suite shows 0 diffs, since everything still falls back to Django; schema guard clean | Next |
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
| M16 | Remaining apps (admin, endpoints, recovery, tenants API, …) | all | Feature matrix 100 % of non-blocked rows verified | |
| M17 | Remove adapters (Django fallback, pyo3, Python worker); hardening, fuzzing, benchmarks, release | all | No Python in the image; full suites green; rollback drill | |

## Risks and decisions needing the project owner

- **R1 — Expression policies and property mappings are user-written Python.** `authentik/lib/expression` evaluates Python source stored in the database, with authentik-specific context objects, for `ExpressionPolicy`, every `PropertyMapping` type (OAuth scopes, SAML, LDAP, SCIM, RADIUS, …), prompt fields, and blueprints `!Context`/`!Format`. Existing databases carry arbitrary Python. A runtime without Python cannot evaluate these with identical semantics. Options:
  (a) keep CPython embedded (pyo3) only as the expression sandbox, so behavior is identical but Python is not fully gone;
  (b) implement a Python-subset interpreter in Rust, with partial parity and existing expressions possibly breaking;
  (c) declare the feature blocked.
  Until decided, every feature that evaluates expressions stops at **Implemented, unverified**.
- **R2 — Enterprise code (`authentik/enterprise/`, 12 930 lines, 20 apps).** Under the EE license a Rust port is a modification owned by Authentik Security Inc., usable only with a valid subscription and not distributable. All EE rows are **Blocked with documented evidence** until the owner confirms a subscription/agreement, or decides to exclude them.
- **R3 — Shared database during transition.** Python and Rust write the same rows. Every model port must prove round-trip byte equality (M4) before any Rust write path is enabled.
- **R4 — Kerberos** needs MIT krb5 bindings. Pure-Rust options are limited, so this may require FFI.
