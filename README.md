# authentik in Rust

A compatibility-preserving reimplementation of [authentik](https://github.com/goauthentik/authentik) in Rust. The pinned upstream release (`UPSTREAM.lock`: `version/2026.2.7`, the version production apps.mysoc.id runs) is the behavioral specification. The PostgreSQL schema, API, protocols and UI stay exactly as upstream.

**Status:** early. 1 of 102 inventoried features is verified equivalent. See [docs/COMPATIBILITY_REPORT.md](docs/COMPATIBILITY_REPORT.md) and [CHECKPOINT.md](CHECKPOINT.md).

| Path | Content |
| --- | --- |
| `docs/` | Audit and contract documents, feature matrix |
| `baseline/` | Schema, API and inventory baselines extracted from the reference |
| `rust/` | Cargo workspace |
| `tests/differential/` | Scripts that run cases on the reference and compare them with Rust |
| `reference/` | Compose file for the upstream reference stack (`.env` is local and gitignored) |
| `scripts/` | Upstream bootstrap, inventory extraction, matrix generation |
| `upstream/` | Pinned upstream checkout (gitignored; `scripts/bootstrap-upstream.sh`) |
