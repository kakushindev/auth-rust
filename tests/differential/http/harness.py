#!/usr/bin/env python3
"""HTTP differential harness: replay identical requests against the reference
and candidate stacks and report every difference.

A second, independent reference process (ref2) restored from the same
snapshot establishes the noise floor: a difference kind that also appears
between ref and ref2 is upstream nondeterminism (per-process hash seeds,
CSRF tokens, clocks). Each case lands in exactly one bucket:
  equal            ref == cand
  nondeterministic every ref/cand difference kind also differs ref/ref2
                   (reported, never counted as verified)
  different        a ref/cand difference kind that ref2 does not show

Standard library only. Cases come from the pinned OpenAPI operation list
(every GET without path parameters, anonymous and with the bootstrap token)
plus the non-API surface (flows, interfaces, well-known, static, health).

Normalization is deliberately narrow and listed in NORMALIZED_HEADERS and
`normalize_json`; anything else that differs is reported.
"""

import argparse
import gzip
import json
import pathlib
import re
import socket
import sys
import urllib.error
import urllib.request
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[3]

# Headers whose values are per-request by design; their presence is still compared.
NORMALIZED_HEADERS = {"date", "x-authentik-id", "x-request-id", "set-cookie", "content-length"}
# Hop-by-hop / transport headers that say nothing about application behavior.
IGNORED_HEADERS = {"connection", "keep-alive", "transfer-encoding"}

NON_API_CASES = [
    "/",
    "/-/health/live/",
    "/-/health/ready/",
    "/if/flow/default-authentication-flow/",
    "/if/admin/",
    "/if/user/",
    "/flows/-/default/authentication/",
    "/api/v3/flows/executor/default-authentication-flow/?query=",
    "/.well-known/webfinger",
    "/robots.txt",
    "/static/dist/poly.js",
    "/application/o/authorize/",
    "/application/o/token/",
    "/does-not-exist/",
    "/api/v3/does-not-exist/",
    "/api/v3/core/users/me/",
    "/api/v3/schema/",
]


GZ = {"Accept-Encoding": "gzip"}
DEFLATE = {"Accept-Encoding": "deflate"}
JS = "/static/dist/poly-2026.2.7.js"
FUTURE = "Fri, 01 Jan 2100 00:00:00 GMT"
PAST = "Sat, 01 Jan 2000 00:00:00 GMT"

# Front-server behavior: static files, compression, framing, preconditions,
# ranges, path cleaning, methods and forwarded headers.
# (auth, method, path, extra request headers)
FRONT_CASES = [
    ("anon", "GET", JS, {}),
    ("anon", "GET", JS, GZ),
    ("anon", "GET", JS, DEFLATE),
    ("anon", "HEAD", JS, {}),
    ("anon", "HEAD", JS, GZ),
    ("anon", "POST", JS, {}),
    ("anon", "GET", JS + ".map", {}),
    ("anon", "GET", JS + ".LEGAL.txt", {}),
    ("anon", "GET", "/static/dist/styles/static-2026.2.7.css", GZ),
    ("anon", "GET", "/static/dist/assets/fonts/RedHat/RedHatTextVFModified-52CCP6M7.woff2", {}),
    ("anon", "GET", "/static/authentik/sources/github.svg", {}),
    ("anon", "GET", "/static/authentik/sources/ldap.png", GZ),
    ("anon", "GET", "/static/dist/admin", {}),
    ("anon", "GET", "/static/dist/admin?x=1", {}),
    ("anon", "GET", "/static/dist/admin/", {}),
    ("anon", "GET", "/static/dist/", {}),
    ("anon", "GET", "/static/dist/index.html", {}),
    ("anon", "GET", "/static/dist/nope.js", GZ),
    ("anon", "GET", "/static/dist/../../etc/passwd", {}),
    ("anon", "GET", "/static/dist/%2e%2e/x", {}),
    ("anon", "GET", "/api/v3//root/config/", {}),
    ("anon", "GET", "/if/flow/default-authentication-flow/assets/nope.js", {}),
    ("anon", "GET", "/if/admin/assets/nope.js", {}),
    ("anon", "GET", "/files/media/nope.png", {}),
    ("anon", "GET", "/files/media/", {}),
    ("anon", "GET", JS, {"Range": "bytes=0-9"}),
    ("anon", "GET", JS, {"Range": "bytes=-5"}),
    ("anon", "GET", JS, {"Range": "bytes=999999999-"}),
    ("anon", "GET", JS, {"Range": "bytes=x"}),
    ("anon", "GET", JS, {"Range": "bytes=0-9", **GZ}),
    ("anon", "GET", JS, {"If-Modified-Since": FUTURE}),
    ("anon", "GET", JS, {"If-Modified-Since": PAST}),
    ("anon", "GET", JS, {"If-Modified-Since": FUTURE, "Cache-Control": "no-cache"}),
    ("anon", "GET", JS, {"If-None-Match": "*"}),
    ("anon", "GET", JS, {"If-None-Match": '"nope"'}),
    ("anon", "GET", JS, {"If-Match": '"nope"'}),
    ("anon", "GET", JS, {"If-Unmodified-Since": PAST}),
    ("anon", "GET", "/robots.txt", GZ),
    ("anon", "HEAD", "/robots.txt", {}),
    ("anon", "GET", "/.well-known/security.txt", {}),
    ("anon", "GET", "/-/health/live/", GZ),
    ("anon", "HEAD", "/-/health/live/", {}),
    ("anon", "GET", "/-/health/ready/", GZ),
    ("anon", "GET", "/api/v3/root/config/", GZ),
    ("anon", "GET", "/api/v3/root/config/", DEFLATE),
    ("anon", "HEAD", "/api/v3/root/config/", {}),
    ("anon", "PROPFIND", "/", {}),
    ("anon", "BREW", "/api/v3/root/config/", {}),
    ("anon", "GET", "/if/admin/", GZ),
    ("token", "GET", "/api/v3/core/users/impersonate_end/", GZ),
    ("token", "GET", "/api/v3/admin/file/", {"X-Forwarded-Proto": "https"}),
    ("token", "GET", "/api/v3/outposts/instances/default_settings/", {"X-Forwarded-Host": "other.test"}),
    ("token", "GET", "/api/v3/core/applications/?page_size=100", GZ),
]


# Protocol switches (method UPGRADE: a raw GET handshake, see `fetch_upgrade`).
WS = {"Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13"}
WS_DEFLATE = {**WS, "Sec-WebSocket-Extensions": "permessage-deflate; client_max_window_bits"}
ZERO_UUID = "00000000-0000-0000-0000-000000000000"
UPGRADE_CASES = [
    ("anon", "UPGRADE", "/ws/client/", WS),
    ("anon", "UPGRADE", "/ws/client/", WS_DEFLATE),
    ("token", "UPGRADE", "/ws/client/", WS_DEFLATE),
    ("anon", "UPGRADE", "/ws/client/", {**WS, "Connection": "keep-alive, upgrade", "Upgrade": "WebSocket"}),
    ("anon", "UPGRADE", f"/ws/outpost/{ZERO_UUID}/", WS),
    ("token", "UPGRADE", f"/ws/outpost/{ZERO_UUID}/", WS),
    ("anon", "UPGRADE", "/ws/nope/", WS),
    ("anon", "UPGRADE", "/api/v3/root/config/", WS),
    ("anon", "UPGRADE", "/api/v3/root/config/", {"Connection": "Upgrade", "Upgrade": "h2c"}),
    ("anon", "UPGRADE", "/ws/client/", {**WS, "Connection": "keep-alive"}),
    ("anon", "UPGRADE", "/ws/client/", {**WS, "Upgrade": "caf\xe9"}),
]


def cases():
    ops = json.loads((ROOT / "baseline/inventory/openapi_operations.json").read_text())["operations"]
    paths = sorted({o["path"] for o in ops if o["method"] == "GET" and "{" not in o["path"]})
    out = [("anon", "GET", p, {}) for p in NON_API_CASES]
    out += [("token", "GET", p, {}) for p in NON_API_CASES]
    for p in paths:
        url = "/api/v3" + p
        out.append(("anon", "GET", url, {}))
        out.append(("token", "GET", url, {}))
    return out + FRONT_CASES + UPGRADE_CASES


def web_path_cases(prefix):
    """Paths at the edges of a non-default web.path (no trailing slash,
    outside it, or doubled)."""
    return [
        "/",
        prefix,
        prefix + "/",
        "/-/health/live/",
        "/-/health/ready/",
        "/static/dist/poly.js",
        "/api/v3/root/config/",
        "/robots.txt",
        "/if/flow/default-authentication-flow/",
        prefix + prefix + "/",
        prefix + "/static/dist/poly.js",
        prefix + "/media/",
        "/media/",
        "/outpost.goauthentik.io/ping",
        prefix + "/outpost.goauthentik.io/ping",
    ]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


# Every stack receives the same Host so host-derived URLs are comparable.
HOST = "authentik.test"


def fetch(base, path, token, method="GET", extra=None):
    headers = {"Accept": "application/json, text/html;q=0.9", "Host": HOST, **(extra or {})}
    req = urllib.request.Request(base + path, headers=headers, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        resp = OPENER.open(req, timeout=60)
    except urllib.error.HTTPError as err:
        resp = err
    body = resp.read()
    headers = {}
    for k, v in resp.headers.items():
        headers.setdefault(k.lower(), []).append(v)
    return resp.status, headers, body


WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="


def read_until_closed(sock, limit):
    data = b""
    while len(data) < limit:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def fetch_upgrade(base, path, token, extra):
    """Raw HTTP/1.1 upgrade handshake. On 101 the body records the frame the
    server answers a websocket Close (1000) with, proving bytes flow both ways
    through the switched connection."""
    host, port = base.removeprefix("http://").split(":")
    lines = [f"GET {path} HTTP/1.1", f"Host: {HOST}", "Accept: application/json, text/html;q=0.9"]
    if token:
        lines.append(f"Authorization: Bearer {token}")
    if "Sec-WebSocket-Version" in extra:
        lines.append(f"Sec-WebSocket-Key: {WS_KEY}")
    lines += [f"{k}: {v}" for k, v in extra.items()]
    sock = socket.create_connection((host, int(port)), timeout=10)
    try:
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        status_line, *header_lines = head.decode("latin-1").split("\r\n")
        status = int(status_line.split()[1])
        headers = {}
        for line in header_lines:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
        if status == 101:
            # Masked close frame, status code 1000, zero mask.
            sock.sendall(bytes([0x88, 0x82, 0, 0, 0, 0, 0x03, 0xE8]))
            sock.settimeout(5)
            frame = rest + read_until_closed(sock, 2 + 125)
            body = b"switched; close reply " + frame[:4].hex().encode()
        elif "content-length" in headers:
            length = int(headers["content-length"][0])
            sock.settimeout(5)
            body = (rest + read_until_closed(sock, length - len(rest)))[:length]
        else:
            sock.settimeout(5)
            body = rest + read_until_closed(sock, 1 << 20)
        return status, headers, body
    finally:
        sock.close()


# Lists Django builds from a set, so their order follows the process's
# string hash seed (`users/me/`'s `system_permissions` comes from
# `get_all_permissions()`): compared as sorted, i.e. as the same multiset.
SET_ORDERED_KEYS = {"system_permissions"}


def normalize_json(value):
    """Recursively blank fields that are generated per request, and put
    set-ordered lists in a canonical order."""
    if isinstance(value, dict):
        return {
            k: (
                "<normalized>"
                if k in {"request_id"}
                else sorted(v)
                if k in SET_ORDERED_KEYS and isinstance(v, list) and all(isinstance(x, str) for x in v)
                else normalize_json(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [normalize_json(v) for v in value]
    return value


# Per-request Sentry trace id rendered into every HTML page (32 hex - 16 hex).
SENTRY_TRACE = re.compile(rb'(<meta name="sentry-trace" content=")[0-9a-f]{32}-[0-9a-f]{16}(")')


def normalize_html(body):
    return SENTRY_TRACE.sub(rb"\1<normalized>\2", body)


def cookie_shape(values):
    """Cookie names and attributes, without the (random) values."""
    shapes = []
    for v in values:
        name, _, rest = v.partition("=")
        attrs = sorted(a.strip().split("=")[0].lower() + ("=" + a.split("=", 1)[1].strip() if "=" in a and not a.strip().lower().startswith("expires") else "") for a in rest.split(";")[1:])
        shapes.append(f"{name}; " + "; ".join(attrs))
    return sorted(shapes)


def kind(diff):
    """The category of a difference, without its values."""
    if diff.startswith("header "):
        return "header:" + diff.split()[1].rstrip(":")
    return diff.split()[0] + ("-body" if "body" in diff else "")


def decoded_body(headers, body):
    """Compare content, not compressor output (Go's and Rust's deflate
    implementations legitimately produce different bytes)."""
    encoding = (headers.get("content-encoding") or [""])[0]
    try:
        if encoding == "gzip" and body:
            return gzip.decompress(body)
        if encoding == "deflate" and body:
            return zlib.decompress(body, -15)
    except (OSError, zlib.error, EOFError):
        return b"<undecodable " + encoding.encode() + b" body>"
    return body


def compare(ref, cand):
    diffs = []
    (rs, rh, rb), (cs, ch, cb) = ref, cand
    if rs != cs:
        diffs.append(f"status {rs} != {cs}")
    names = (set(rh) | set(ch)) - IGNORED_HEADERS
    for name in sorted(names):
        if (name in rh) != (name in ch):
            diffs.append(f"header {name} only in {'reference' if name in rh else 'candidate'}")
        elif name == "set-cookie":
            if cookie_shape(rh[name]) != cookie_shape(ch[name]):
                diffs.append(f"set-cookie shape {cookie_shape(rh[name])} != {cookie_shape(ch[name])}")
        elif (
            name == "content-length"
            and "content-encoding" not in rh
            and "content-encoding" not in ch
            and rh[name] != ch[name]
        ):
            # Lengths only legitimately differ for compressed bodies.
            diffs.append(f"header content-length: {rh[name]} != {ch[name]}")
        elif name not in NORMALIZED_HEADERS and rh[name] != ch[name]:
            diffs.append(f"header {name}: {rh[name]} != {ch[name]}")
    rb, cb = decoded_body(rh, rb), decoded_body(ch, cb)
    ctype = (rh.get("content-type") or [""])[0]
    if "json" in ctype:
        try:
            if normalize_json(json.loads(rb)) != normalize_json(json.loads(cb)):
                diffs.append("json body differs")
        except ValueError:
            if rb != cb:
                diffs.append("body differs (invalid json)")
    elif normalize_html(rb) != normalize_html(cb):
        diffs.append(f"body differs ({len(rb)} vs {len(cb)} bytes)")
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reference", default="http://127.0.0.1:29000")
    ap.add_argument("--candidate", default="http://127.0.0.1:29100")
    ap.add_argument("--reference2", default="http://127.0.0.1:29200")
    ap.add_argument("--token-env-file", default=str(ROOT / "reference/.env"))
    ap.add_argument("--report", default=None)
    ap.add_argument(
        "--prefix",
        default="/",
        help="web.path of all three stacks: every case is replayed under it, plus the prefix edge cases",
    )
    args = ap.parse_args()

    env = dict(
        line.split("=", 1) for line in pathlib.Path(args.token_env_file).read_text().splitlines() if "=" in line
    )
    token = env["AUTHENTIK_BOOTSTRAP_TOKEN"]

    # Self-test: a seeded difference must be detected, otherwise the run is void.
    probe = fetch(args.reference, args.prefix.rstrip("/") + "/api/v3/root/config/", None)
    if compare(probe, probe):
        sys.exit("harness self-test failed: identical responses reported as different")
    status, headers, body = probe
    doc = json.loads(body)
    doc["__seeded__"] = True
    seeds = {
        "json value": (status, headers, json.dumps(doc).encode()),
        "header": (status, {**headers, "x-frame-options": ["SEEDED"]}, body),
        "status": (status + 1, headers, body),
    }
    for name, seeded in seeds.items():
        if not compare(probe, seeded):
            sys.exit(f"harness self-test failed: seeded {name} difference not detected")

    results = []
    prefix = args.prefix.rstrip("/")
    all_cases = cases()
    if prefix:
        all_cases = [(who, method, prefix + path, extra) for who, method, path, extra in all_cases]
        all_cases += [(who, "GET", path, {}) for who in ("anon", "token") for path in web_path_cases(prefix)]
    for who, method, path, extra in all_cases:
        tok = token if who == "token" else None
        get = (lambda base: fetch_upgrade(base, path, tok, extra)) if method == "UPGRADE" else (
            lambda base: fetch(base, path, tok, method, extra)
        )
        ref, ref2, cand = get(args.reference), get(args.reference2), get(args.candidate)
        diffs = compare(ref, cand)
        noise = compare(ref, ref2)
        noise_kinds = {kind(d) for d in noise}
        if not diffs:
            bucket = "equal"
        elif all(kind(d) in noise_kinds for d in diffs):
            bucket = "nondeterministic"
        else:
            bucket = "different"
        results.append(
            {
                "auth": who,
                "method": method,
                "path": path,
                "headers": extra,
                "status": ref[0],
                "bucket": bucket,
                "diffs": diffs,
                "noise": noise,
            }
        )
        if bucket == "different":
            print(f"DIFF {who:5} {method} {path} {extra or ''}: " + "; ".join(diffs))

    buckets = {}
    statuses = {}
    for r in results:
        buckets[r["bucket"]] = buckets.get(r["bucket"], 0) + 1
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    failed = [r for r in results if r["bucket"] == "different"]
    summary = {
        "cases": len(results),
        "buckets": dict(sorted(buckets.items())),
        "reference_status_histogram": dict(sorted(statuses.items())),
        "nondeterministic_cases": sorted(
            f"{r['auth']} {r['method']} {r['path']} {r['headers'] or ''}".strip()
            for r in results
            if r["bucket"] == "nondeterministic"
        ),
        "normalized_headers": sorted(NORMALIZED_HEADERS),
        "normalized_json_fields": ["request_id"],
        "normalized_html": ["meta sentry-trace content"],
    }
    print(json.dumps(summary))
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps({"summary": summary, "results": results}, indent=1) + "\n")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
