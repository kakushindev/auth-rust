# Test strategy

## Environments

| Environment | What | Where |
| --- | --- | --- |
| Reference | `ghcr.io/goauthentik/server:2026.2.7` + PostgreSQL 16, bound to 127.0.0.1 only (HTTP 19000, HTTPS 19443, PG 15432) | `reference/compose.yml`, secrets in `reference/.env` (gitignored, generated locally) |
| Candidate | Rust build + same PostgreSQL major version, restored from the same snapshot | planned (M2) |
| Scratch | throwaway databases inside the reference PG container (`ak_guard_scratch`, …), dropped after use | ad hoc |

The reference snapshot is never modified by tests. Destructive tests run only against scratch copies.

## Layers

1. **Unit tests** in each crate (`cargo test --workspace`).
2. **Fixture-based differential tests.** A script runs inside the reference container and records Django's output for a case matrix. The Rust test replays the matrix and requires exact equality, including which cases raise. Example: `tests/differential/passwords/` → `rust/crates/ak-passwords/tests/django_differential.rs`.
3. **Reverse interop.** Rust produces artifacts (hashes, tokens, cookies, signed documents), and the reference consumes them with its own code.
4. **Real-data checks.** Rust reads rows the reference wrote (e.g. the `akadmin` password hash).
5. **HTTP differential harness (M3).** It replays requests against reference and candidate, compares status, headers and body after normalizing nondeterministic fields (with their invariants checked separately), then compares the DB state diff of both sides and the emitted `authentik_events_event` rows.
6. **Upstream suites as oracles.** `tests/e2e` (Selenium), `tests/openid_conformance` (OIDF), and upstream unit tests ported per feature.
7. **Schema gate.** `ak-schema-guard verify` against the baseline before and after each candidate run. Drift fails the run.
8. **Property-based tests and fuzzing.** Parsers (SAML, OAuth requests, LDAP BER, RADIUS packets, hash strings) get `proptest`/`cargo-fuzz` targets once they exist.

## Commands

```bash
./scripts/bootstrap-upstream.sh                 # pinned upstream checkout
docker compose -f reference/compose.yml --env-file reference/.env up -d
./tests/differential/passwords/run.sh           # password hasher differential (3 directions)
(cd rust && cargo test --workspace && cargo clippy --workspace --all-targets)
DATABASE_URL=… rust/target/debug/ak-schema-guard verify --baseline baseline/schema/reference-schema.json
python3 scripts/gen_feature_matrix.py           # regenerate docs/FEATURE_MATRIX.md
```

## Read API differential (M7)

`tests/api/run.sh` populates a snapshot (tests/models, tests/rbac, tests/api tokens), runs reference, second reference and candidate from it, and replays `tests/api/api_diff.py`'s cases for every subject token. The candidate runs with `AUTHENTIK_RS_API_TRACE=1`, so Rust-served responses carry `X-Authentik-Rs`; the harness strips that header before comparing and counts it, so a silent fallback to Django cannot pass as coverage.


The harness runs tokens concurrently (`API_JOBS`, default 8, which matches gunicorn's 2 workers × 4 threads per stack). Every token keeps the suite's case order, so its own side effects (Django deletes an expired token on first use) happen at the same point on every stack. A sequential warm-up first runs each token's first case on all three stacks, so those one-time effects are settled before tokens interleave. Evidence that this changes nothing: on the same candidate image the sequential run (`API_JOBS=1`) and the parallel run produced identical buckets, and an identical Rust-served set over the 11 067 cases common to both runs. Cases that are not common carry run-specific fixture UUIDs in their paths. A full run takes about 15 minutes instead of about 50.

Speed-ups, each shown on one fixture to decide what the previous run decided:
- **Concurrent fetching.** Each case asks the three stacks at once (`API_CASE_SERIAL=1` restores one after another). Every stack still receives every token's requests in suite order.
- **Concurrency settings.** `API_JOBS=16`, and `WEB_WORKERS` sets gunicorn's workers alike on every stack.
- **Cached fixture.** The populated snapshot and session cookies are cached for at most 6 hours (`API_FRESH=1` rebuilds). The cache key covers the reference database's exact contents (one `pg_dump`, hashed as the SQL it restores to, without pg_dump's random `\restrict` token), the image, the populate and session scripts, `run.sh` and the compose file. It leaves out only the data of the tables the reference's worker keeps rewriting (tasks, schedules, worker status, cache entries), which stay in the fixture. A fixture holding an older copy of those tables is as valid a fixture.
- **Comparing reports.** `tests/api/compare_reports.py` compares two runs case by case, by endpoint, token and position, since fixture rows get new keys when it is rebuilt. It checks the reference status, whether Rust served each case and the bucket. On one cached fixture, the old pipeline (serial per case, 8 jobs, a 4-connection Rust pool) and the new one decided all 15 768 cases identically (0 differ). The new run took 995 s against 1 101 s; the fixture is 1–2 s cached, 50 s built.

The limit was the candidate, not Django. In a sampled run, the candidate container used about 2 cores and its database 1.3, while each reference used about 0.5. A Rust-served request first took about twice Django's time, because the vendored pool closed its connection after every query (about 11 new PostgreSQL connections per request). With the read API's persistent pool (`ak_common::db::api_pool`, COMPATIBILITY_REPORT), a Rust-served request takes 4–9 ms against Django's 45–71 ms. The cases phase of a full run is now **418 s** (about 1 300 s at the start for the whole run), still 15 768/15 768 equal.

`rbac/permissions` can be nondeterministic at a page boundary: Django orders by `name` alone, five permission names are duplicated, and PostgreSQL breaks ties as its plan does. The two references then disagree as well, which is what the noise bucket records.

`users/me/` used to be the only nondeterministic endpoint: Django builds `system_permissions` from a set, so its order follows the process's hash seed. The harness now compares that list sorted, i.e. as the same multiset, and a full run is 15 768/15 768 equal.


Session and CSRF variants run alongside the tokens. `tests/api/sessions.py` creates real sessions on the reference before the snapshot is dumped. They are labels in `api_diff.py` (`cookie:…`, `cookie+bearer:…`, `csrf:…`) and cover every fifth case of each endpoint: what they exercise is the middleware, so a sample of each endpoint is enough.

Inputs where Django's own answer depends on the process are left out of the case list, and Rust declines them; each is listed with a comment in `api_diff.py`. One example is several invalid values for a `ModelMultipleChoiceFilter`, where Django reports whichever value comes first in a `frozenset`, so the order follows the per-process string hash seed.

## Write differential (M8)

`tests/writes/write_diff.py` runs after the read suite on the same three stacks (`API_SUITES="reads writes"` by default, `API_SUITES=writes` alone). `capture.sql` installs a trigger on every public table that appends each row change (table, operation, old and new row as JSON) to `m8cap.changes`. Cases run one at a time on each stack, and the harness collects that case's changes right after its response. `uncapture.sql` removes the triggers before the schema guard runs.

Normalization, and nothing more:
- A UUID or 32-hex value absent from that stack's `pg_dump` before the suite becomes `<idN>`, numbered per stack in order of appearance.
- A timestamp from the case's start onward becomes `<now>`.
- A `bytea` task message becomes `<bytea>` (tests/events checks it byte for byte).
- The embedded outpost's state heartbeat in the cache table is dropped.

A fixture value referenced wrongly stays a literal mismatch, and a created value referenced wrongly is a number mismatch. Before the summary, a self-test seeds five differences into an equal case (a changed value, a dropped row, reversed rows, a renumbered reference, a status) and fails the run unless every one is detected.

## Rules

- A test that cannot detect a difference does not count. Each differential suite needs at least one seeded-failure check, as the schema guard drift test does.
- Normalization is limited to genuinely random or time-based values and is listed per suite.
- Never weaken a security check to make a comparison pass. Differences in security decisions are release-blocking.
