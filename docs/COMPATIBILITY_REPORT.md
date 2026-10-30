# Compatibility report

As of 2026-10-30, against authentik `version/2026.2.7` (`0936c5b0`), the version production `apps.mysoc.id` runs. Re-pinned from 2026.8.5 on the owner's decision.

## Bottom line

The rewrite is at the start. **1 of 102 inventoried features is Verified equivalent** (the password hasher contract, re-verified at 2026.2.7). 17 are blocked by the Enterprise license, and 84 are not started. No HTTP endpoint, flow, protocol, worker task or outpost has been ported. The candidate application does not exist yet. 100 % equivalence is not claimed for anything beyond the components listed below.

## Verified

| Component | Evidence (commands actually run) | Result |
| --- | --- | --- |
| `ak-passwords` (Django `PASSWORD_HASHERS`) | `tests/differential/passwords/run.sh` | 152/152 encodings identical; 65/65 `verify_password` outcomes identical incl. exceptions; 31/31 Rust hashes accepted by Django; reference `akadmin` hash verifies. `cargo test -p ak-passwords`: 14 tests pass. |
| `ak-schema-guard` (tooling) | `snapshot`/`verify` on reference; restored dump; injected drift | Restored copy matches fingerprint `8afc1fc8…`; injected column-type change and extra index both detected. 3 unit tests pass. |
| Candidate server vs 2026.8.5 (superseded) | `tests/differential/http/run.sh` against the 2026.8.5 reference | 461 equal, 9 nondeterministic, 0 different. Upstream 2026.8.5 already fronted Django with this same Rust server, so this only proved the vendoring. |
| Shipped-binary provenance (REA `inspect_rust_binary`, evidence `ev_01f6978c…`) | `/bin/authentik` copied from the reference image | No cargo-auditable section. rustc commit `8bab26f4…` = toolchain 1.97.1; all 153 crate versions embedded in panic paths match the pinned `Cargo.lock`. Inference only, not a reproducible build. |

Differences found by differential testing and fixed (they would otherwise have shipped):
1. scrypt parallelism is 5 in the installed Django, not 1.
2. `verify_password(pw, None)` raises `TypeError`; it does not return False.
3. argon2-cffi reports libargon2 decode failures as a mismatch (False) and only raises on an unknown type header.
4. Django runs a dummy default hash for unusable or unknown hashes (timing equalization), and calls `identify_hasher` even when the password is `None`.


## Open: Rust server vs the 2026.2.7 Go front server (M2)

At 2026.2.7 upstream fronts Django with the **Go** `authentik` binary. Our Rust server replaces it in `candidate/Dockerfile`. Fixed so far: a bare `authentik` invocation now means `server` (the 2026.2.7 `lifecycle/ak` calls it without arguments, and the Rust binary used to exit); the reported version is now 2026.2.7.

`tests/differential/http/run.sh` (440 cases, 3 stacks; the schema guard is clean on all 3) still reports every case as different. The differences, by kind:

| # | Difference (reference = Go, candidate = Rust) | Cases | Upstream source to match |
| --- | --- | ---: | --- |
| 1 | `Server: uvicorn` from gunicorn reaches the client only through Rust | 432 | `internal/web/proxy.go` |
| 2 | Go compresses proxied responses and always sends `Vary: Accept-Encoding`; Rust does not compress proxied responses | 432 | `internal/web/web.go` (compress handler) |
| 3 | `/-/health/live/`, `/-/health/ready/`: Go answers `live` itself and forwards `ready` to Django (security headers, `content-type`, `x-authentik-id`); Rust answers both itself and adds `x-powered-by` | 8 | `internal/web/proxy.go` |
| 4 | `/robots.txt`: `text/plain` vs `text/plain; charset=utf-8`; Go sends `ETag` | 2 | `internal/web/static.go` |
| 5 | Static 404 (`/static/dist/poly.js`): Go returns a 19-byte `404 page not found` body; Rust returns an empty body plus `Cache-Control` | 2 | `internal/web/static.go` |
| 6 | `impersonate_end`: Rust adds `Content-Length` | 1 | proxy response copying |

Further known gaps, not yet covered by the harness: listen-address config format (2026.2.7 uses scalars like `0.0.0.0:9000` where the Rust loader expects lists, and Go binds IPv4 only); the `healthcheck worker` semantics; metrics on `:9300` (Rust reads them via pyo3); brand TLS SQL against the 2026.2.7 schema; and the embedded outpost (Go proxyv2 vs the Rust proxy).

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
