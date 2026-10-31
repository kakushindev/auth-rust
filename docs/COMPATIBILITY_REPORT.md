# Compatibility report

As of 2026-10-30, against authentik `version/2026.2.7` (`0936c5b0`), the version production `apps.mysoc.id` runs. Re-pinned from 2026.8.5 on the owner's decision.

## Bottom line

The rewrite is at the start. **1 of 102 inventoried features is Verified equivalent** (the password hasher contract, re-verified at 2026.2.7). 17 are excluded as Enterprise (owner decision R2: kept separate), and 84 are not started. No HTTP endpoint, flow, protocol, worker task or outpost has been ported. The candidate application does not exist yet. 100 % equivalence is not claimed for anything beyond the components listed below.

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

`tests/differential/http/run.sh` (3 stacks from one snapshot, 504 cases: every parameterless GET API operation anonymous and with a token, plus 53 front-server cases covering static files, gzip/deflate, HEAD, ranges, preconditions, redirects, unclean paths, unknown methods and forwarded headers, plus 11 protocol-upgrade cases): **496 equal, 8 nondeterministic (also differing between two upstream processes), 0 different** (batch 5). The schema guard is clean on all databases.

Reviewed deviation: storage tokens keep upstream Rust's stricter validation (HS256, required `exp`/`nbf`). Every token 2026.2.7 issues passes it.

### Listen addresses (batch 5)

2026.2.7 configures each listener as one Go address string (`listen.http: 0.0.0.0:9000`), and Go's `net.Listen` binds a wildcard as `[::]` with `IPV6_V6ONLY` cleared (dual-stack, whatever `net.ipv6.bindv6only` says). Upstream Rust only accepted lists of socket addresses and bound `0.0.0.0` IPv4-only. Now:
- `listen.http`/`https`/`metrics` accept a scalar or a list. Each entry is resolved like Go's `SplitHostPort` + `parsePort` + `LookupPort` (an empty, `+` or `-` port means a random port; a sign and leading zeros are accepted; the range is 0–65535). An empty host is the wildcard, an IPv4-mapped literal is IPv4, `::` becomes `0.0.0.0` (Go issue 18806), and a hostname resolves to its first IPv4 address (`ak-common` `parse_go_listen_addr`).
- Binding follows `favoriteAddrFamily`: a wildcard is `[::]` dual-stack, falling back to `0.0.0.0` without kernel IPv6. `SO_REUSEADDR` is set, with a `somaxconn` backlog. Accepted connections get Go's `TCP_NODELAY` and keep-alive settings (idle 15 s, interval 15 s, count 9). HTTPS raises the idle time to 3 min (`TCPKeepAliveListener`). Before this, the Rust server set neither option.
- The compiled-in defaults are 2026.2.7's (`0.0.0.0:9000`, `:9443`, `:9300`).

Evidence: a candidate container started with a 2026.2.7 scalar `/etc/authentik/config.yml` (`http: 0.0.0.0:9000`, `https: ":9443"`, `metrics: 127.0.0.1:9300`) listens on `[::]:9000` and `[::]:9443` dual-stack and on `127.0.0.1:9300`, as Go does. Upstream Rust rejected this config. `tests/differential/listen/run.sh` records Go 1.25.5's actual `net.Listen` for 32 addresses (family, bound IP, port, `IPV6_V6ONLY`, or failure) in `golang:1.25.5-alpine`, and replays them through the Rust parser and binder: all 32 match. In the candidate container, `/proc/net/tcp6` shows the same `[::]` listeners on 9000/9300/9443 as the Go reference. Unit tests cover the accepted-socket options and scalar/list/invalid YAML.

Deviations (reviewed, kept): Go resolves a service-name port (`:http`) and Rust rejects it. An empty address means "no listener" here, while Go listens on a random port. A comma-separated env value binds every entry, where Go fails to listen. An invalid address fails config loading, where Go logs a warning and runs without that listener. A bind failure stops the process, where Go logs and continues.

### Protocol upgrades / websockets (batch 5)

Batch 4 regressed every websocket. `remove_hop_by_hop` stripped `Connection`/`Upgrade` before the upgrade check, so Django received the handshake as a plain GET and answered 200 (the embedded outpost's `HTTP error: 200 OK`; `/ws/client/` was affected too). The HTTP harness had no upgrade cases. `forward_request` now ports `ReverseProxy`'s upgrade handling. It records `upgradeType` before stripping and re-adds `Connection: Upgrade` + `Upgrade` afterwards. A non-printable protocol is refused with the Go error text. On a 101 it checks that the backend switched to the requested protocol, returns the backend's 101 headers as-is (apart from `ModifyResponse`), and splices both connections byte for byte with half-close propagation. Upstream Rust's websocket proxy, which re-framed messages and stripped `Sec-WebSocket-Extensions`, is no longer used. The harness gained 11 raw-socket upgrade cases. On a 101, each one sends a websocket Close and compares the echoed frame. Against the batch-4 candidate, 9 of them differ; after the fix, all 11 are equal. The embedded outpost now connects (`connected to websocket`), and `/api/v3/outposts/instances/<embedded>/health/` lists the instance at version 2026.2.7, as on the reference.

### Health checks (batch 6)

`ak healthcheck` runs `authentik healthcheck <mode>`, with the mode read from `$TMPDIR/authentik-mode`. In 2026.2.7 the worker is Python (`python -m manage worker --pid-file …`) in its own pod, and the Helm chart's worker liveness probe is this command. Upstream Rust checked every mode over the server's unix socket, which a worker pod doesn't have, so every worker probe would have failed and the pods would have restarted in a loop. `healthcheck` now ports Go's `cmd/server/healthcheck.go`:
- `server`: `HEAD http://<listen.http><web.path>-/health/live/` over TCP, following redirects with no timeout; status < 400 is healthy.
- `worker`: `$TMPDIR/authentik-worker.pid` must name a process that accepts signal 0 (`Atoi` parsing; PIDs 0 and -1 are refused as `os.Process` refuses them).
- Any other mode exits 1.

Evidence: in containers of both images on the same database, `ak healthcheck` exits identically in all four cases (server alive: 0; worker alive: 0; worker with a stale PID: 1; worker with no PID file: 1). The mode file now has 2026.2.7's trailing newline.

### Metrics on :9300 (batch 6)

2026.2.7's Go server serves only `/metrics` (anything else gets Go's `404 page not found`, and unclean paths get mux's 301). The body is its own registry through `promhttp` (text 0.0.4, `escaping=underscores`), followed by Django's `/-/metrics/`, fetched with a bearer key from `$TMPDIR/authentik-core-metrics.key`. Upstream Rust answered on every path, never wrote that key file, so Django's `MetricsView` failed, and the IPC key Django reads at import was missing too. Now:
- `prepareKeys`: both key files are written (64 random bytes, base64, 0600) before gunicorn starts and removed on shutdown.
- `/metrics` re-renders the Rust registry as `client_golang` does. Families are sorted, metrics sorted by label values, labels by name (`le` last), values formatted with `FormatFloat('g', -1)` (checked against Go 1.25.5), and histograms use `DefBuckets`. It adds the `process_*` collector (procfs semantics, `userHZ` = 100) and `promhttp_metric_handler_*`, then appends Django's body.
- `authentik_main_request_duration_seconds` is observed only for proxied core requests and the embedded outpost, as Go does: not for static files, `/-/health/live/`, startup 503s or unsupported-method 501s.
- `authentik_outpost_connection` drops the `version`/`build` labels, and `authentik_outpost_last_update` keeps sub-second precision (`SetToCurrentTime`).

Evidence: `tests/differential/metrics/compare.py` checks status, headers and 404 bodies for 5 paths, plus HELP/TYPE/label names for every family and the order of the front server's families. Reference vs candidate after the HTTP differential's traffic: 0 differences over 47 families (15 front-server). Reference vs a second reference: also 0, after treating Django's family order as a set; that order differs between two Go processes.

Deviation (unavoidable): Go's 29 `go_*` runtime families have no Rust equivalent and are not emitted. A Prometheus `Accept` asking for protobuf gets text here.

### Brand TLS on :9443 (batch 7)

Upstream Rust's brand TLS differed from 2026.2.7's Go `GetConfigForClient` in selection, client-certificate handling and the TLS surface. It is now a port (`src/brands/tls.rs`, `src/server/tls.rs`, `ak-axum` `LazyTlsAcceptor`), with one configuration per ClientHello:
- **Selection (`brand_tls.Watcher`):** brands in API order (`domain`). Every brand is a candidate: the pinned Go API client marks `web_certificate` as set even when it is `null` (checked in `goauthentik.io/api/v3` at the go.mod version). The last default brand, then the last brand whose domain is a plain suffix of the SNI (no dot boundary), wins. With no SNI, the default brand is used.
- **Certificates (`CryptoStore`):** keyed by the stored `fingerprint_sha256`; a keypair with an empty stored fingerprint is never loaded, and a changed keypair that fails to load keeps the previous one. Without a private key the leaf is only usable as a client CA, and as a web certificate the handshake fails, as in Go. The check runs when Django is up, then every 3 minutes.
- **Client certificates:** only for the selected brand, `RequestClientCert` semantics: the CA subjects are sent, any certificate (or none) is accepted without chain verification, and the CertificateVerify signature is still checked. The certificate reaches Django as `X-Forwarded-Client-Cert`.
- **TLS surface (`GetTLSConfig` + `GOFIPS=1`, which the 2026.2.7 image sets):**
  - TLS 1.2/1.3; TLS 1.3 AES-GCM; TLS 1.2 ECDHE AES-GCM; groups P-256/P-384, chosen in server order (AES-128 first).
  - Signatures and requested client-cert signatures use Go's scheme order (PSS-SHA256 first; no PKCS#1 in TLS 1.3).
  - One session ticket, with a 7-day hint in TLS 1.3 and none in TLS 1.2, written right after the handshake. Ticket keys are shared across connections.
- **Fallback certificate:** as Go's: RSA-2048, `authentik default certificate`, SAN `*`, critical Basic Constraints encoded `30 00`, no key identifiers.

Evidence: `tests/differential/tls/brands.sh` seeds identical keypairs and brands into ref, ref2 and cand. The seed covers RSA and ECDSA certificates, a keypair without a key, an empty stored fingerprint, a client-certificate-only brand and the default brand. The script compares 11 SNIs (certificate, client CA names, requested signature algorithms, acceptance of an unrelated client certificate) plus the probe of versions, ciphers, groups, the default negotiation, signatures and tickets (`probe.sh`). Reference vs candidate: identical; reference vs reference: identical.

Deviations (reviewed, kept):
- Go sends its TLS 1.3 ticket in the server's first flight; rustls sends it after the client Finished, one round trip later. A client that closes immediately misses it.
- rustls ticket keys rotate every 6 hours, so resumption works for about 12 hours where Go allows 7 days.
- Without `GOFIPS=1`, Go would also offer TLS 1.2 CBC and RSA key-exchange suites, which rustls does not implement.
- SNI matching is case-insensitive in rustls (it lowercases); Go compares as sent.
- The fallback certificate lists SAN first (rcgen's order).
- A brand change is picked up within 3 minutes; Go also re-checks on every embedded-outpost refresh.

### Non-default `web.path` (batch 7)

With `web.path` other than `/`, gorilla mux in 2026.2.7 routes only `/` (an `http.Redirect` 302 to `web.path`, with Go's HTML body) and the prefix. Everything else gets `http.NotFound` without the router's middleware. The health route is `<web.path>-/health/live/`, since gorilla prepends the prefix template to the later `Path`, and it probes Django at `<web.path>-/health/live/`. The embedded outpost's ping exists only at `/outpost.goauthentik.io/ping` under the default path. All of this is ported. Evidence: `WEB_PATH=/authentik/ tests/differential/http/run.sh` replays all 504 cases under the prefix plus 15 prefix-edge paths, anonymous and with a token: 534 cases, 530 equal, 4 nondeterministic, 0 different. The schema guard is clean.

### Forwarded headers, 502s, gunicorn, embedded outpost (batch 8)

- **Forwarded headers, as Django sees them.** `tests/differential/http/forwarded.py` (run by `run.sh`) sends 21 header combinations (`X-Forwarded-For`/`-Proto`/`-Host`/`-Scheme`, `X-Real-IP`, `Forwarded`, mTLS headers, outpost IP override, user agents) and compares the client IP, scheme, host, user agent and status in each server's Django log. Trusted peer (default CIDRs): 21/21 identical. `TRUSTED_CIDRS=127.0.0.1/32 run.sh` (harness host untrusted): 21/21 identical, and the 504 HTTP cases are also identical under that configuration. The script checks that the mode is really in effect.
- **502 text.** `proxyErrorHandler`'s message now carries Go's transport error, `dial unix $TMPDIR/authentik-core.sock: connect: <errno>`, and the JSON variant uses `encoding/json`'s HTML escaping. `tests/differential/http/backend_down.sh` makes the socket missing, then a non-socket file: JSON and text 502s identical.
- **gunicorn** starts as gounicorn starts it: `gunicorn -c ./lifecycle/gunicorn.conf.py authentik.root.asgi:application --pid $TMPDIR/authentik-gunicorn.<n>.pid`, bound by the config to `authentik-core.sock`. Upstream Rust passed its own `--bind …/authentik-gunicorn.sock`.
- **Embedded outpost transport.** Like Go, it reaches core over TCP at `http://<listen.http><web.path>`, through the front server (API, websocket, OAuth backchannel), not the server's unix socket. It fetches `root/config` at start, and the websocket sends the outpost user agent and only `instance_uuid`. Django previously recorded the outpost as client `255.255.255.255` on host `localhost`; now it records `127.0.0.1` on `0.0.0.0:9000`, as with Go. `tests/differential/http/outpost_requests.py`: the outpost's requests as Django logs them are identical, also under `web.path=/authentik/`.

Deviation (kept): with `debug: true` Go runs `./manage.py dev_server` and talks to it over TCP; the Rust server always runs gunicorn on the socket. Production never sets `debug`.

- **Embedded outpost hello** (owner decision 2026-10-31: report the same as Go). `golangVersion` `go1.25.5` (the 2026.2.7 build's runtime), `opensslEnabled` false, `opensslVersion` from `/usr/bin/openssl version` as Go runs it, and `fipsEnabled` from `GOFIPS=1`. Django's stored `OutpostState` for the embedded outpost is identical between reference and candidate.

Still open in M2: `%q` quoting of non-ASCII Unicode format characters in upgrade errors is approximate.

## Models (M4)

`rust/crates/ak-models` is the storage layer for the identity tables: 80 row types, one per table (core users, groups and their M2M tables, applications, entitlements, tokens, sessions, providers and sources with all non-Enterprise subclasses and runtime rows, brands, tenants, and the policy-binding parent). `scripts/gen_models.py` generates them from the pinned schema snapshot with each column's exact Postgres type: jsonb as its exact text (`RawValue`), so numerals are never renumbered; inet, bytea and text[] map exactly too. Unknown types fail generation. `inheritance::resolve` gives a row's most-derived Django class, Enterprise subclasses included.

Evidence: `tests/models/run.sh` restores a reference snapshot, populates it through Django's ORM (`tests/models/populate.py`: every model type, NULLs, unicode, nested JSON with 20- and 30-digit integers, IPv4/IPv6, binary session data, group hierarchies, one Enterprise provider) and runs `cargo test -p ak-models` against it:
- All 282 rows of all 80 tables decode.
- In one rolled-back transaction, every row written back by primary key, then every table deleted and re-inserted from the decoded rows, leaves all tables and the group-ancestry view byte-equal as Postgres renders them, and every deferred foreign key holds. A seeded difference (a 30-digit integer passed through f64) is detected.
- The class of each of the 79 rows in the provider, source, property-mapping and source-connection hierarchies equals Django's `select_subclasses()`.

Not yet covered: typed domain models (enums, validation) and the behavior built on them start in M5.

## Request identity (M5, part 1)

`rust/crates/ak-auth` decides, as 2026.2.7's Django does:
- **`host::get_host`**: Django 5.2's host validation with `ALLOWED_HOSTS = ["*"]`, i.e. Python lowercasing then `^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9.:]+\])(?::([0-9]+))?$`. It returns the raw host. `tenant_hostname` drops the port and a leading `www.` (django-tenants).
- **`brand::resolve`**: `get_brand_for_request`, using Django's exact SQL (`UPPER`, `LIKE` with escaped `%`/`_`, longest domain first, then the default brand). It compares the raw `get_host()`, so a port in `Host` defeats a portless domain.
- **`tenant::resolve`**: `DefaultTenantMiddleware.get_tenant` (the exact domain, else the public tenant).
- **`token::bearer_auth`**: `TokenAuthentication.bearer_auth`. It covers Python's `str.strip`/`split` whitespace (including U+001C..U+001F) and the API token, OAuth access token (`icontains` then an exact scope check), secret key and IPC key paths. An inactive user fails. A revoked access token still authenticates, as in Django. A non-UTF-8 header and non-ASCII `compare_digest` input are Django 500s (`UnicodeDecodeError`, `TypeError`).

Evidence: `tests/auth/run.sh` populates a snapshot with brands (case, ports, `_`, `%`, Unicode), a tenant domain, and tokens and access tokens in every state. Django decides every vector inside a rolled-back transaction. 25 hosts (`get_host`, brand, tenant hostname, tenant) and 34 `Authorization` headers: all identical. The outcomes cover every path (6 distinct brands, default fallback, `DisallowedHost`, API token, JWT, secret key, IPC, failures, both exception kinds).

Deferred to the write layer (M8): Django deletes expired tokens and access tokens it encounters while authenticating (through the ORM, which cascades to `FlowToken` and writes an audit event), and creates the embedded outpost's service user if missing. `ak-auth` makes the same decision (expired is absent; `SecretKey { user: None }`) without those writes. They must exist before Rust serves authenticated routes (M7).

## Sessions (M5, part 2)

`ak_auth::session::resolve` decides a request's identity from its `authentik_session` cookie as 2026.2.7's middleware chain does: `ClientIPMiddleware`, `BoundSessionMiddleware`, `AuthenticationMiddleware`, then `ImpersonateMiddleware`'s check.
- **Cookie**: `SessionMiddleware.decode_session_key`, i.e. PyJWT 2.11 `decode(cookie, sha512(SECRET_KEY).hexdigest(), ["HS256"])`. That covers PyJWT's segment splitting, Python 3.14's lenient urlsafe base64, the header checks (`dict`, `b64`, `alg`), HMAC, and the claim checks: `iat`/`nbf`/`exp` through `int()`, a truthy `aud` rejected, and non-`str` `sub`/`jti` rejected. Then `SessionStore`'s `key and len(key) >= 8`. The JSON is CPython's (`python.rs`): NaN/Infinity, lone surrogates, duplicate keys with the last winning, the 4300-digit limit, and a nesting limit at the image's measured recursion depth. The parser is iterative and its values drop iteratively, so a crafted cookie cannot overflow the stack. Python exceptions that escape (`TypeError`, `OverflowError`, `UnicodeEncodeError`) are Django 500s and are returned as such.
- **Store**: the session row with `expires > now`, joined to `AuthenticatedSession` and its user. An inactive user is a logout with 400. Session data is read by `ak-pickle`, a pickle reader for protocols 2–5 that never executes anything. It covers memo sharing, model instances (`model_unpickle`), `SimpleLazyObject`, enum members, and dict and list subclasses such as `QueryDict` that take items through `__setitem__`. It is checked against CPython on 39 vectors.
- **Impersonation**: the pickled user under `authentik/impersonate/user` replaces the authenticated one.

Evidence: `tests/auth/run.sh` makes real sessions over HTTP through the flow executor. These are an anonymous in-flow session, a login, two concurrent logins of one user, one of them then impersonating, a session whose user is then deactivated, a logged-out session, and a session that is then expired. Around a real session key it adds 45 crafted JWTs: claims, header, algorithm and signature variants, deep nesting, and every exception path. All 54 cookies (including an absent one) resolve as Django decides. All 33 keys in the 7 session rows read as Django decodes them (type, and value or length).

Known approximations:
- `int()` on non-ASCII decimal digits in a claim.
- The JSON nesting limit depends on the runtime stack (measured 47,405–47,449 in the image; Rust uses 47,000).
- A pickle `ak-pickle` cannot read is an empty session. Django returns an empty session only for `PickleError`/`AttributeError`/`TypeError`, so a pickle that makes Python raise anything else is a 500 there.

## Bindings, CSRF, cookies and client IP (M5, part 3)

- **Client IP** (`ak_auth::client_ip`): `ClientIPMiddleware`. It takes the first `X-Forwarded-For` address, else `REMOTE_ADDR`, as `str(ip_address(…))` (IPv6 compressed, scope kept), else `255.255.255.255`. The outpost override (`X-authentik-remote-ip` with `X-authentik-outpost-token`) applies only for an unexpired API token of an internal service account. The outpost user is set even when the delegated IP does not parse.
- **GeoIP** (`rust/crates/ak-geoip`): a MaxMind DB reader matching `maxminddb` 3.0 (search tree, IPv4-in-IPv6 start node, prefix lengths, every data type, pointers), plus what `geoip2` 5.2 builds from a record. That is the ASN number and network, and the continent, country and city records compared by `to_dict()` equality. It also follows authentik's `MMDBContextProcessor` (reload on a newer mtime, unconfigured when unreadable). On the image's GeoLite2 databases, 4,328 addresses look up identically, raw records and models alike (`tests/geoip/run.sh`).
- **Bound sessions** (`ak_auth::binding`): `BoundSessionMiddleware.recheck_session`, all network and GeoIP modes. It returns the break reason (`network.missing`, `network.asn`, `network.asn_network`, `network.ip`, `geoip.*`), or a pass that updates `last_ip` when a binding key is present. A broken binding answers `redirect_to_login(request.get_full_path())`. The redirect uses Django's `escape_uri_path`/`iri_to_uri`/`repercent_broken_unicode` and gunicorn's path decoding (`ak_auth::url`).
- **CSRF** (`ak_auth::csrf`): `CsrfViewMiddleware` with authentik's settings (cookie `authentik_csrf`, header `X-authentik-CSRF`, no trusted origins), and DRF's `enforce_csrf`. It covers the secret format, masking and unmasking, the Origin check, and the Referer check over TLS (CPython 3.14's `urlsplit`/`geturl`, checked on 455 vectors, NFKC included). It also covers token checks from the form or header, every rejection message, and DRF's body parse errors escaping the check.
- **Response cookies** (`ak_auth::cookie`): Django's `set_cookie`/`delete_cookie`, rendered as Python's `Morsel.OutputString` (sorted attributes, quoting with octal escapes, `CookieError` on control characters), `patch_vary_headers` and `http_date`. On top of these:
  - `SessionMiddleware.process_response`: delete when the session is empty; otherwise save and set a PyJWT-encoded session cookie with `SameSite`/`Secure` by TLS and `Max-Age` from `_session_expiry`.
  - authentik's `is_secure`.
  - The CSRF cookie refresh.

Evidence (`tests/auth/run.sh`, with time frozen on both sides):
- **Sessions**: real sessions are bound by `bind_sessions.py`, then requested from other client IPs, including an impersonating one and ones with an expiry. All 81 cookies resolve as Django decides: unchanged, passed with the `last_ip` update, broken by ASN, network, IP, continent, city or a missing lookup, redirect included. All 75 resulting session cookies, `Vary` values and saves are identical.
- **Request/response pieces** (`web_decide.py`), all identical:
  - 190 CSRF requests, each through both Django and DRF;
  - 65 token/secret cases and 50 cookie, Vary and date cases;
  - 397 `process_response` cases;
  - 80 `is_secure` cases and 18 login redirects;
  - 1,613 binding rechecks on the real databases;
  - 77 client IPs.
- **On the wire**: 13 answers from the running server are reproduced, namely CSRF 403 details through DRF's `SessionAuthentication`, the replacement CSRF cookie, and the session cookie deletion over HTTP and over TLS.

Left to other milestones:
- The write layer (M8): saving or flushing the session, the `user_logged_out` event a broken binding records, and deleting expired tokens.
- The request layer (M7): parsing form bodies for `csrfmiddlewaretoken` (the check takes the parsed value) and the WSGI `url_scheme`.
- Routes (M7, M9): which views are `csrf_exempt`, and the flow executor, which does not enforce CSRF.

Approximations:
- A pickled `datetime` as `_session_expiry` is treated as the cookie age; Django 5 stores ISO strings.
- An MMDB map with non-string keys is a `TypeError`.

## Permissions (M6)

`rust/crates/ak-rbac` decides permissions as 2026.2.7 does. authentik grants them only through roles, which come from the user and from the user's groups and their ancestors (`authentik_core_groupancestry`). A superuser group, also inherited, grants everything. The auth backends grant nothing; only the `ak-guardian` fork's `ObjectPermissionBackend` does. The crate covers:
- **`has_perm` / `has_perms`**: `PermissionsMixin`'s active-superuser shortcut (which `AnonymousUser` lacks; guardian reads the `AnonymousUser` row for it). Then guardian's `WrongAppError`, the inactive and superuser checks, and the union of model-wide and per-object permissions of the user's roles. A codename without an app label matches any app.
- **`get_objects_for_user`**:
  - Errors: `GuardianError`, `MixedContentTypeError`, and `DoesNotExist`/`MultipleObjectsReturned` from the permission's content type.
  - Superusers skip the active check, so an inactive superuser still sees everything.
  - Model-wide permissions count for every object.
  - With several permissions, the row count is reproduced: the same permission through two roles satisfies two.
  - The final `pk IN (… ::uuid | ::bigint …)` query runs as Django runs it. Postgres therefore raises `DataError` for an `object_pk` that does not cast, and `ProgrammingError` for a model with a text primary key.
- **`ObjectFilter`**: all with the global view permission, then the owner field, then guardian's objects; an empty result is a 403, except for internal service accounts.
- **DRF**: `ObjectPermissions.has_permission`, which allows any lookup, allows create without permission where the view opts in, and requires authentication, with `MethodNotAllowed`. Also `has_object_permission`: global first, then the owner, then the object; `Http404` for reads, a 403 for writes.
- **`@permission_required`**.

Evidence: `tests/rbac/run.sh` takes rows of every model type (`tests/models/populate.py`) and a fixture with:
- roles holding model-wide permissions;
- per-object permissions on two rows of every model;
- a three-level group hierarchy, and superuser groups held directly and through a child group;
- duplicate grants, an uncastable `object_pk`, and inactive, service-account and impersonated users;
- Django's `AnonymousUser`.

Every decision for the 14 subjects is identical to Django's: 10,500 global and 13,538 object `has_perm` checks, 7,686 `get_objects_for_user`, 2,533 `ObjectFilter`, 3,360 `ObjectPermissions` and 378 `permission_required` decisions.

Left to other milestones:
- `InitialPermissionsMiddleware`, which assigns permissions on create, is a write (M8).
- Which views use which lookup, owner field or create flag is route configuration (M7).
- `get_objects_for_user` returns the matching primary keys rather than a composable filter. M7 will need it as SQL for paginated lists.

## Read API (M7)

New crate `rust/crates/ak-api`. The server's `read_api` hook (`src/server/core.rs`) runs after the request is rewritten into exactly what Django receives (forwarded headers, Host), and only for the routes in `src/server/compat.rs` `PORTED_ROUTES`. `ak-api` either produces Django's response or **declines before doing anything**, and the request then goes to Django unchanged. Declines cover:
- session cookies (sessions write, M8);
- languages other than `en`/`en-US`;
- `Accept` headers other than JSON (with no media-type parameters);
- `?format=`;
- non-default tenants or `web.path`;
- any Enterprise license row;
- tokens Django would delete while looking them up;
- outpost or IPC identities;
- inputs whose Python parsing is not ported (non-ASCII digits, `int(…, 16)` UUID syntax);
- Django's own 500s (an invalid `groups` UUID);
- more than 1000 query fields.

Ported: DRF content negotiation; authentik's `TokenAuthentication` (403 rather than 401, as there is no `authenticate_header`); `ObjectPermissions`; the Enterprise search app's backend order. Without a license that order is `QLSearch`, which defers to DRF `SearchFilter` (`smart_split`, NUL → 400 list body), then `ObjectFilter` (403 when nothing is visible), django-filter, and `OrderingFilter`. Also ported: `AutocompletePagination` (`autocomplete: {}` for views without QL fields) with the tenant's page sizes, and Django's `QueryDict`, `int()`, `Decimal()` (including django-filter's `MaxValueValidator(1e50)` against the exact float), `NullBooleanSelect`, `uuid.UUID(hex=)` and `prep_for_like_query`.

| Route | Evidence | Result |
| --- | --- | --- |
| `GET /api/v3/rbac/roles/`, `GET /api/v3/rbac/roles/{pk}/` | `tests/api/run.sh` (3 stacks from a snapshot populated by tests/models, tests/rbac and tests/api: 13 subjects with API tokens, plus no/invalid/expired/recovery tokens; 66 list queries covering pagination, ordering, search, every `RoleFilterSet` field and its invalid values, combined errors and repeated parameters; and retrieve for every role plus malformed and missing pks) | **1 870 / 1 870 equal**; 1 831 answered by Rust (marked with `X-Authentik-Rs` under `AUTHENTIK_RS_API_TRACE`), and the 39 declines answered by Django; schema guard clean on all 3 databases |
| `GET /api/v3/rbac/permissions/`, `/{pk}/` | same suite: every page at sizes 100 and 7 (permission names repeat, so the SQL is Django's own text so that ties come back in Django's order), all ordering sources, multi-field search, each filter including invalid and missing roles, retrieve with `int()` edge pks and duplicate-name rows | **1 241 / 1 241 equal, all answered by Rust** |
| `GET /api/v3/rbac/initial_permissions/`, `/{pk}/` | same suite; tests/api/populate.py adds three rows, one with an object-level grant; nested `permissions_obj` uses `Permission`'s default ordering | **459 / 459 equal**, 452 by Rust (`ordering=permissions`, a duplicating m2m join, is declined) |
| `GET /api/v3/core/brands/`, `/{pk}/` | same suite; tests/api/populate.py adds brands with every relation set, two client certificates, a duplicated domain and an object-level grant. Cases cover each of the 15 generated filters (UUID, char, `BooleanWidget`, FK and m2m model choices with invalid, missing, non-canonical and repeated values), m2m search through Django's `EXISTS`, ordering by FK columns, and `brands/current/` (a `detail=False` action, left to Django) | **1 360 / 1 360 equal**, 1 276 by Rust. Declines: pages containing the m4 brand whose `attributes` hold an integer orjson rejects (Django answers 500 there), `ordering=client_certificates` (a duplicating join), and two invalid m2m values (Django reports one by hash order) |
| `GET /api/v3/events/transports/`, `/{pk}/` | same suite; every `TransportMode`, webhook mappings, `send_once`; `ChoiceFilter` (unstripped, case-sensitive), `BooleanWidget`, three-field search | **952 / 952 equal**, 935 by Rust (`used_by/` is not ported) |
| `GET /api/v3/propertymappings/notification/`, `/{pk}/` | same suite; multi-table inheritance join to `authentik_core_propertymapping` | **289 / 289 equal, all answered by Rust** |
| `GET /api/v3/crypto/certificatekeypairs/`, `/{pk}/` | same suite; generated RSA/ECDSA/Ed25519 pairs, a certificate without key, NULL metadata, a microsecond expiry; the `managed` JWT key excluded; `has_key` (`NullBooleanSelect`) and `key_type` (`MultipleChoiceFilter`, first invalid value in request order) | **918 / 918 equal**, 901 by Rust (`generate/` is not ported) |
| `GET /api/v3/core/users/`, `/{pk}/` | same suite; tests/api/populate.py adds users whose names cover the initials avatar (multi-part, `ß`→`SS`, final sigma, `&`/`<`, emoji and Greek as lxml's ASCII character references), attribute avatars (string, empty, a non-dict walk), memberships of a superuser child group and of roles; the tenant tries `attributes.m7.avatar,gravatar,initials`. Cases cover pagination, `include_groups`/`include_roles` (prefetch versus per-user queries), every `UsersFilter` field with its invalid values, and `AgentAuth`'s scheme | **1 496 / 1 496 equal or nondeterministic** (3 are `me/`, Django-served), 1 383 by Rust. Declines: the `attributes` and date filters (`IsoDateTimeField` parsing is not ported), `ordering` on the `is_superuser`/`uid` properties or on m2m fields, pages Django 500s on (orjson-unrenderable `jsonb`), and avatar cache misses |
| `GET /api/v3/core/groups/`, `/{pk}/` | same suite; `include_users`/`include_children`/`include_parents`/`include_inherited_roles` in every combination, `GroupFilter` (int-keyed and username-keyed member filters), search over `is_superuser::text` | **850 / 850 equal**, 796 by Rust (`attributes`, out-of-range member ids, `ordering=num_pk`/m2m, `used_by/` declined) |
| `GET /api/v3/core/tokens/`, `/{identifier}/` | same suite; `lookup_field = "identifier"`, `owner_field = "user"` (no 403 without the global permission: the user's own tokens), `user_obj` through `UserSerializer` without prefetches (per-user group and role queries, as `token.user` gives them), the single `user` join shared by search and `user__username` | **901 / 901 equal**, 832 by Rust. Declines: the `expires` date filter, and anonymous requests that reach the owner filter (`filter(user=AnonymousUser())` is Django's own 500) |
| `GET /api/v3/events/events/`, `/{pk}/` | same suite; tests/api/populate.py adds events with a fixed action, so their lists stay stable while the stacks log events of their own. Cases cover the JSON lookups (`context #> '{model,pk}'` as text or `int()`, `user`/`context -> 'username'`, `brand -> 'name'`), `client_ip` (inet text, `HOST()` in search), `MultipleChoiceFilter` on `EventAction`, and `detail=False` actions | **782 / 782 equal**, 751 by Rust; the `autocomplete` (R2) includes the `SELECT DISTINCT app` options. Declines: IPv6 or invalid `client_ip` filter values (normalization, or Django's DataError 500) |
| `GET /api/v3/events/notifications/`, `/{pk}/` | same suite; notifications of every severity, with and without an event (`EventSerializer` per row) and links; `owner_field`; no `ordering` on the view, so pages keep Django's own SQL (unordered) | **629 / 629 equal**, 594 by Rust. Declines: the `created` date filter, anonymous retrieves at the owner filter (Django 500), and `mark_all_seen/` |
| `GET /api/v3/events/rules/`, `/{pk}/` | same suite; `PolicyBindingModel` parent join; `destination_group_obj` through `GroupSerializer` without prefetches; the group join is `LEFT OUTER` for search and demoted to `INNER` by the filter, after `ObjectFilter`'s `exists()` | **612 / 612 equal**, 604 by Rust (`ordering=transports` is declined) |

Also ported for these: Django's `jsonb` → `json.loads` → orjson rendering (`ak_api::json`: key order, int/float split, `ryu` float forms as checked against orjson in the image), and the generated app/model verbose-name registry (`scripts/gen_api_registry.py`). The model field's message `“x” is not a valid UUID.` wins over the choice field's "Select a valid choice".

Upstream behavior reproduced as is: `users=<id>&inherited=true` (and `groups=…&inherited=true`) replaces the queryset with `all_roles()`, dropping the search and object-permission restriction; `users=1.5` matches user 1; `managed=None` matches the NULL choice text.

**R2, reproduced:** `core/users`, `core/groups` and `events/events` return the QL `autocomplete` object that the Enterprise search app builds even without a license (owner decision 2026-10-31; specified in MIGRATION_PLAN R2).

**Router order** matters beyond `detail=False` actions. DRF registers `rbac/permissions/assigned_by_roles` and `rbac/permissions/roles` before `rbac/permissions`, so those paths belong to other viewsets and are not `rbac/permissions/{pk}/`; Rust declines them (regression cases in `permission_cases`). A scan of every `api_urlpatterns` shows no other ported prefix shadowed this way.

**Not in M7:** `core/applications`. Its list runs `PolicyEngine` for every application (expression policies are Python), caches the result as pickled `Application` objects, and formats `launch_url` with user data. It moves to the policy-engine milestone.

**Avatars** (`ak_api::avatar`, `ak_api::cache`): every mode of `get_avatar` is reproduced. Initials SVGs are byte-identical to lxml's ASCII serialization, colours come from `md5(name.lower())`, and strings lxml rejects are declined (Django answers 500). URL modes (`gravatar`, `…://…`) read Django's `django_postgres_cache` rows: keys are `public::1:goauthentik.io/lib/avatars/<host>/…` and values are pickles, decoded for `None`, bools and `str`. On a hit Rust makes Django's own writes, `touch` (expiry = now + 300 s, Django's default timeout) and the deletion of expired rows, after every avatar on the page has been resolved. A miss means Django would send an outbound `HEAD` and cache the result, so Rust declines and Django answers and fills the cache.

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
- **R2 — Enterprise license**: decided 2026-10-31, kept separate. Enterprise is not ported; its 17 rows are "Excluded (separate)".
