# Database contract

The PostgreSQL schema produced by authentik 2026.8.5 migrations is **immutable**
for the Rust implementation. Rust code reads and writes these tables as they
are; it never creates, alters or drops schema objects.

## Baseline artifacts

| File | Content | How it was produced |
| --- | --- | --- |
| `baseline/schema/reference-schema.sql` | `pg_dump --schema-only --no-owner --no-privileges` (13 553 lines) | `pg_dump` inside the reference `postgresql` container after `server` finished migrating |
| `baseline/schema/django_migrations.tsv` | 777 `(app, name)` rows applied in `public` | `psql` against the reference |
| `baseline/schema/reference-schema.json` | Canonical catalog snapshot, fingerprint `8afc1fc82567d9b2db45f8a7ff94318f272653c20206fa7ba3222ef1ad8a1e30` | `ak-schema-guard snapshot` |

## What the fingerprint covers

`rust/crates/ak-schema-guard` reads `pg_catalog` in a read-only session and records, for every non-system schema and excluding extension-owned objects:

| Section | Objects | Attributes compared |
| --- | ---: | --- |
| schemas | 2 | `public`, `template` (django-tenants template schema) |
| relations | 291 | kind (table/view/matview/sequence/foreign), persistence, access method |
| columns | 1 387 | logical position (ignoring dropped columns), `format_type`, NOT NULL, default expression, identity, generated, collation |
| constraints | 756 | type, `pg_get_constraintdef`, deferrable/deferred |
| indexes | 827 | `pg_get_indexdef` |
| sequences | 60 | type, start, increment, min, max, cache, cycle, owning column |
| types | 0 | enums (labels in order), domains, standalone composites, ranges |
| functions | 6 | identity arguments, kind, `pg_get_functiondef` |
| triggers | 5 | `pg_get_triggerdef`, enabled state |
| views | 1 | `pg_get_viewdef` |
| extensions | 1 | `plpgsql 1.0` |
| django_migrations | 777 | applied migration identifiers per schema |

The baseline file embeds per-section sha256 fingerprints; `verify` refuses a baseline whose fingerprints do not match its contents.

Verified on 2026-10-30:
- A full `pg_dump` restored into a scratch database matches the baseline exactly (fingerprint equal).
- After `ALTER COLUMN username TYPE varchar(200)` and an extra index, `verify` reports both changes (`~ public.authentik_core_user.username`, `+ public.ak_drift_idx`) and exits non-zero.

```bash
DATABASE_URL=postgres://… rust/target/debug/ak-schema-guard verify --baseline baseline/schema/reference-schema.json
```

Running `verify` before and after every candidate test run is mandatory (see `TEST_STRATEGY.md`).

## Database-side behavior Rust must not duplicate or bypass

These are executed by PostgreSQL itself and stay in force regardless of the application language:

| Trigger | Table | Purpose |
| --- | --- | --- |
| `pgtrigger_refresh_groupancestry_62450` | `authentik_core_groupparentage` | refreshes the `authentik_core_groupancestry` materialized view after any parentage change |
| `pgtrigger_set_next_run_on_paused_95c6d` | `authentik_tasks_schedules_schedule` | when a schedule is paused, adjusts `next_run` |
| `pgtrigger_notify_enqueueing_0bc94` | `authentik_tasks_task` | `NOTIFY` for the Postgres task broker |
| `pgtrigger_update_aggregated_status_f18c4` | `authentik_tasks_task` | maintains aggregated task status |
| `pgtrigger_notify_new_channels_message_d21ae` | `django_channels_postgres_message` | `NOTIFY` for the channels layer (websockets) |

`_pgtrigger_should_ignore(name)` lets django-pgtrigger skip triggers per session; the Rust implementation must not set that GUC unless upstream does in the same situation.

## Application-level behavior on top of the schema (to be contracted per model)

Django adds behavior the schema does not show. Each must be captured per model before its Rust port is called equivalent:

- Python-side defaults (`default=` callables such as `uuid4`, `generate_id`, `default_token_duration`, `now`), recorded per field in `baseline/inventory/django.json`.
- `save()`/`delete()` overrides and `pre_save`/`post_save`/`m2m_changed`/`pre_delete` signal handlers (e.g. password change signals, event logging, cache invalidation, outpost reconciliation triggers).
- Multi-table inheritance: `Provider`, `Source`, `Stage`, `Policy`, `PropertyMapping`, `Authenticator`-style hierarchies are stored as one parent row plus one child row sharing the primary key; deletes cascade parent ↔ child.
- django-model-utils `InheritanceManager` (`select_subclasses`) ordering and child resolution.
- `SerializerModel`/`ManagedModel` (`managed` column) used by blueprints.
- `ExpiringModel` (`expires`, `expiring`) and the cleanup actors.
- django-guardian object permissions (`guardian_*` tables) and the RBAC role/permission model.
- Encrypted / secret fields and their key derivation from `AUTHENTIK_SECRET_KEY`.
- Session storage: `SESSION_ENGINE = authentik.core.sessions` (DB-backed `Session` model + `AuthenticatedSession`).
- Timezone: Django stores `timestamptz` in UTC; JSON fields use `JSONField` with Django's encoder (UUID/datetime serialization).
- Tenant schema switching (`django-tenants`): `search_path` per request based on the tenant.

## Password hash format (verified)

`authentik_core_user.password` uses Django's default `PASSWORD_HASHERS` (no override): `pbkdf2_sha256` (preferred, 1 000 000 iterations), `pbkdf2_sha1`, `argon2` (argon2id, t=2, m=102400, p=8), `bcrypt_sha256` (12 rounds), `scrypt` (N=16384, r=8, **p=5**). Unusable passwords start with `!`. See `SECURITY_INVARIANTS.md` for the verified behavior.
