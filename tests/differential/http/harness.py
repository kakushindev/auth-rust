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
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[3]

# Headers whose values are per-request by design; their presence is still compared.
NORMALIZED_HEADERS = {"date", "x-authentik-id", "x-request-id", "set-cookie", "content-length", "etag"}
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


def cases():
    ops = json.loads((ROOT / "baseline/inventory/openapi_operations.json").read_text())["operations"]
    paths = sorted({o["path"] for o in ops if o["method"] == "GET" and "{" not in o["path"]})
    out = [("anon", p) for p in NON_API_CASES]
    out += [("token", p) for p in NON_API_CASES]
    for p in paths:
        url = "/api/v3" + p
        out.append(("anon", url))
        out.append(("token", url))
    return out


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


# Every stack receives the same Host so host-derived URLs are comparable.
HOST = "authentik.test"


def fetch(base, path, token):
    req = urllib.request.Request(
        base + path, headers={"Accept": "application/json, text/html;q=0.9", "Host": HOST}
    )
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


def normalize_json(value):
    """Recursively blank fields that are generated per request."""
    if isinstance(value, dict):
        return {k: ("<normalized>" if k in {"request_id"} else normalize_json(v)) for k, v in value.items()}
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
        elif name not in NORMALIZED_HEADERS and rh[name] != ch[name]:
            diffs.append(f"header {name}: {rh[name]} != {ch[name]}")
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
    args = ap.parse_args()

    env = dict(
        line.split("=", 1) for line in pathlib.Path(args.token_env_file).read_text().splitlines() if "=" in line
    )
    token = env["AUTHENTIK_BOOTSTRAP_TOKEN"]

    # Self-test: a seeded difference must be detected, otherwise the run is void.
    probe = fetch(args.reference, "/api/v3/root/config/", None)
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
    for who, path in cases():
        tok = token if who == "token" else None
        ref = fetch(args.reference, path, tok)
        ref2 = fetch(args.reference2, path, tok)
        cand = fetch(args.candidate, path, tok)
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
            {"auth": who, "path": path, "status": ref[0], "bucket": bucket, "diffs": diffs, "noise": noise}
        )
        if bucket == "different":
            print(f"DIFF {who:5} {path}: " + "; ".join(diffs))

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
        "nondeterministic_cases": sorted(f"{r['auth']} {r['path']}" for r in results if r["bucket"] == "nondeterministic"),
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
