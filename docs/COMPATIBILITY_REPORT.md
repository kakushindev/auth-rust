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


## Rust server vs the 2026.2.7 Go front server (M2)

`rust/src/server/go_compat/` ports the Go front-server HTTP behavior from the pinned sources: gorilla `CompressHandler` and `ProxyHeaders`, mux path cleaning, go-http-utils `etag`/`fresh`, and Go 1.25.5 `net/http` FileServer, sniffing, MIME table and response framing, plus the `ReverseProxy` header rules and its retry of replayable requests.

`tests/differential/http/run.sh` (3 stacks from one snapshot, 493 cases: every parameterless GET API operation anonymous and with a token, plus 53 front-server cases covering static files, gzip/deflate, HEAD, ranges, preconditions, redirects, unclean paths, unknown methods and forwarded headers): **484 equal, 9 nondeterministic (also differing between two upstream processes), 0 different**. The schema guard is clean on all databases.

Reviewed deviation: storage tokens keep upstream Rust's stricter validation (HS256, required `exp`/`nbf`). Every token 2026.2.7 issues passes it.

Still open in M2: config format (scalar listen addresses, IPv4-only bind); `healthcheck worker` semantics; metrics on :9300; brand TLS SQL against the 2026.2.7 schema; the embedded outpost (the Rust proxy outpost's websocket fails against 2026.2.7 Django with `HTTP error: 200 OK`); non-default `web.path`; untrusted-proxy header paths (unit-tested only); Go's exact 502 error text.

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
