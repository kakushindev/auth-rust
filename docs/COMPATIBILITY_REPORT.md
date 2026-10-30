# Compatibility report

As of 2026-10-30, against authentik `version/2026.8.5` (`4ec0d19b`).

## Bottom line

The rewrite is at the start. **1 of 105 inventoried features is Verified equivalent** (the password hasher contract). 20 are blocked by the Enterprise license, and 84 are not started. No HTTP endpoint, flow, protocol, worker task or outpost has been ported. The candidate application does not exist yet. 100 % equivalence is not claimed for anything beyond the components listed below.

## Verified

| Component | Evidence (commands actually run) | Result |
| --- | --- | --- |
| `ak-passwords` (Django `PASSWORD_HASHERS`) | `tests/differential/passwords/run.sh` | 152/152 encodings identical; 65/65 `verify_password` outcomes identical incl. exceptions; 31/31 Rust hashes accepted by Django; reference `akadmin` hash verifies. `cargo test -p ak-passwords`: 14 tests pass. |
| `ak-schema-guard` (tooling) | `snapshot`/`verify` on reference; restored dump; injected drift | Restored copy matches fingerprint `8afc1fc8…`; injected column-type change and extra index both detected. 3 unit tests pass. |
| Candidate server (M2): upstream Rust server vendored + empty compat router | `tests/differential/http/run.sh` (3 stacks from one DB snapshot: ref, ref2, cand) | 470 cases (every parameterless GET API operation anonymous + token, plus non-API surface): 461 equal, 9 nondeterministic (the same difference kinds appear between two upstream processes: cache `age`/`expires` on `/api/v3/schema/`, per-process ordering of `system_permissions` in `users/me`, runtime data in `admin/system`, event/task timing), **0 different**. Only normalization: `Date`, request-id headers, cookie values (names and attributes still compared), `request_id`, and the `sentry-trace` meta value. Schema guard matches the baseline on all three databases after the run. |
| Shipped-binary provenance (REA `inspect_rust_binary`, evidence `ev_01f6978c…`) | `/bin/authentik` copied from the reference image | No cargo-auditable section. rustc commit `8bab26f4…` = toolchain 1.97.1; all 153 crate versions embedded in panic paths match the pinned `Cargo.lock`. Inference only, not a reproducible build. |

Differences found by differential testing and fixed (they would otherwise have shipped):
1. scrypt parallelism is 5 in the installed Django, not 1.
2. `verify_password(pw, None)` raises `TypeError`; it does not return False.
3. argon2-cffi reports libargon2 decode failures as a mismatch (False) and only raises on an unknown type header.
4. Django runs a dummy default hash for unusable or unknown hashes (timing equalization), and calls `identify_hasher` even when the password is `None`.


## Not verified / open

- The 9 nondeterministic cases are compared only coarsely, so a real difference inside them would be masked. They need field-level masking, e.g. sorting `system_permissions` after checking set equality.
- Every row of `FEATURE_MATRIX.md` other than the one above.
- The upstream Rust components (server shell, proxy outpost) are reused as-is and have not been re-verified here.
- Lint: `ak-passwords` and `ak-schema-guard` pass clippy with upstream's full lint profile (0 warnings). Generated `client-rust` is not rustfmt-clean upstream either and is left untouched.

## Temporary compatibility adapters (must be removed before the full-Rust milestone)

1. **Django fallback**: `fallback(forward_request)` → gunicorn → Django serves **every** application request today (`PORTED_ROUTES` is empty).
2. **pyo3 / CPython** embedded in the `authentik` binary (`core` feature), plus the Python dramatiq worker.
3. **Go outposts** (LDAP, RADIUS, RAC).

The product is therefore **not yet full Rust**. All three adapters must be removed before the full-Rust milestone (M17).

## Blockers needing a decision

- **R1 — Python expressions**: decided as full Rust; a Rust Python-subset engine is required (M9b).
- **R2 — Enterprise license**: 20 apps blocked pending subscription/agreement confirmation.
