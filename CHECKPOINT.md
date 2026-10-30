# Checkpoint

Durable resume point for the authentik → Rust rewrite. Update at the end of every batch.

## Batch 1 — 2026-10-30

### Completed (all verified by commands that ran in this batch)

- Pinned upstream `version/2026.8.5` = `4ec0d19b98da3c329781894cd550da95d3033954` (`UPSTREAM.lock`, `scripts/bootstrap-upstream.sh`).
- Reference stack running from `reference/compose.yml` (authentik 2026.8.5 + PG 16, localhost-only ports 19000/19443/15432). It migrated cleanly: 777 migrations.
- Baselines: `baseline/schema/` (pg_dump, migration list, canonical JSON snapshot `8afc1fc8…`), `baseline/api/openapi.yml`, `baseline/inventory/` (live Django registry, OpenAPI operations, Go components).
- Audit docs `docs/*.md` (10 required documents) + generated `docs/FEATURE_MATRIX.md`.
- Rust workspace `rust/` (toolchain 1.97.1):
  - `ak-passwords`: verified equivalent to Django 5.2.17 hashers (see `docs/COMPATIBILITY_REPORT.md`).
  - `ak-schema-guard`: snapshot/verify/diff, verified against a restored copy and injected drift.
- `cargo test --workspace` 17 passed; `cargo clippy --workspace --all-targets` 0 warnings; `cargo fmt --check` clean.

### Blockers (need the project owner)

- R1 Python expressions: keep embedded CPython as the sandbox, or not? (`docs/MIGRATION_PLAN.md`)
- R2 Enterprise license: confirm subscription/agreement, or exclude EE.

### Exact next action (M2)

1. Vendor `upstream/src/` (MIT, keep attribution in `NOTICE.md`) into `rust/apps/server`, using `packages/ak-common` and `ak-axum` via path dependencies on `../upstream/packages/*`.
2. Insert an (initially empty) compat router before `fallback(forward_request)` in the vendored `core.rs`.
3. Build a candidate image from the upstream Dockerfile with our binary swapped in, and run it beside the reference on a snapshot copy.
4. Start M3: HTTP differential harness. Its first run must show 0 differences, since everything still falls back to Django, and must detect a seeded difference.

### How to resume

```bash
./scripts/bootstrap-upstream.sh
docker compose -f reference/compose.yml --env-file reference/.env up -d   # .env is local-only; recreate with fresh random values if missing
./tests/differential/passwords/run.sh
```
