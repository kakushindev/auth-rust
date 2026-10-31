#!/usr/bin/env python3
"""M7 read-API differential: the same GET against reference, second
reference (noise floor) and candidate, for every subject token and every
query-parameter edge of each ported endpoint.

Buckets and comparison come from tests/differential/http/harness.py. A case
is only "equal" when status, headers (after the harness's narrow
normalization) and the JSON body match. Every endpoint also gets a check
that the candidate really answered from Rust: tests/api/run.sh starts the
candidate with AUTHENTIK_RS_API_TRACE=1, which adds `X-Authentik-Rs: <route>`
to Rust-served responses; that header is removed before comparison and
counted, so a silent fall-back to Django cannot pass as coverage.
"""

import argparse
import json
import pathlib
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/differential/http"))
import harness  # noqa: E402

REF, REF2, CAND = "http://127.0.0.1:29000", "http://127.0.0.1:29200", "http://127.0.0.1:29100"
TRACE = "x-authentik-rs"

SUBJECTS = [
    "m6-none",
    "m6-direct",
    "m6-grandchild",
    "m6-child-direct",
    "m6-dup",
    "m6-super",
    "m6-super-sub",
    "m6-inactive",
    "m6-inactive-super",
    "m6-service",
    "m6-service-none",
    "m6-broken",
    "akadmin",
]


def admin_get(path):
    status, _, body = harness.fetch(REF, path, "m7-akadmin")
    assert status == 200, (path, status, body[:200])
    return json.loads(body)


def all_results(path):
    sep = "&" if "?" in path else "?"
    return admin_get(f"{path}{sep}page_size=1000")["results"]


def q(**params):
    return "?" + urllib.parse.urlencode(params) if params else ""


def role_cases():
    roles = all_results("/api/v3/rbac/roles/")
    users = {u["username"]: u["pk"] for u in all_results("/api/v3/core/users/?search=m6-")}
    groups = {g["name"]: g["pk"] for g in all_results("/api/v3/core/groups/?search=m6-g")}
    managed = sorted({r.get("managed") for r in roles if r.get("managed")} or {"x"})
    base = "/api/v3/rbac/roles/"
    lists = [
        "",
        q(page=2, page_size=3),
        q(page=0),
        q(page=-1),
        q(page="abc"),
        q(page="last"),
        q(page="2.0"),
        q(page=999),
        q(page_size=0),
        q(page_size=-1),
        q(page_size="abc"),
        q(page_size=" 4"),
        q(page_size=1000000),
        q(page_size=2, page=" 2"),
        q(ordering="-name"),
        q(ordering="pk"),
        q(ordering="-pk"),
        q(ordering="managed"),
        q(ordering="nope"),
        q(ordering="-name,pk"),
        q(ordering=" name , -pk "),
        q(ordering=""),
        q(search="m6"),
        q(search="M6-D"),
        q(search="dup a"),
        q(search="m6,dup"),
        q(search='"m6-dup"'),
        q(search="%"),
        q(search="_"),
        q(search=""),
        q(search="é"),
        q(name="m6-model"),
        q(name="nope"),
        q(name=""),
        q(managed=managed[0]),
        q(managed="bogus"),
        "?managed=" + urllib.parse.quote(managed[0]) + "&managed=bogus",
        q(managed__isnull="true"),
        q(managed__isnull="false"),
        q(managed__isnull="garbage"),
        q(managed__isnull="True"),
        q(managed__isnull="1"),
        q(users=users["m6-direct"]),
        q(users=users["m6-grandchild"], inherited="true"),
        q(users=users["m6-grandchild"], inherited="false"),
        q(users=users["m6-child-direct"], inherited="TRUE"),
        q(users="abc"),
        q(users="1.5"),
        q(users=999999),
        q(users=""),
        q(groups=groups["m6-g-child"]),
        q(groups=groups["m6-g-grandchild"], inherited="true"),
        q(groups="00000000-0000-0000-0000-000000000000"),
        q(groups=""),
        q(search="m6", ordering="-name", page_size=2, page=2),
        q(unknown="1"),
        q(search="a\x00b"),
        q(name="a\x00b"),
        q(groups="a\x00b"),
        q(groups="not-a-uuid"),
        q(groups="{" + groups["m6-g-child"].upper() + "}"),
        q(users="1e0"),
        q(users=" 1 "),
        q(users="Infinity"),
        q(users="NaN"),
        q(users="-1"),
        q(users="99999999999"),
        q(users="1e400"),
        q(users="1e50"),
        q(users="1e51"),
        q(users="-1e400"),
        q(users="100000000000000007629769841091887003294964970946560"),
        q(users="100000000000000007629769841091887003294964970946560.5"),
        q(users="0.0012e3"),
        q(users="1_0"),
        q(users=" "),
        q(managed="None"),
        q(managed="null"),
        q(managed=""),
        "?managed=bogus&users=abc&name=a%00b",
        "?ordering=pk&ordering=-name",
        "?page=2&page=1&page_size=3",
        "?page_size=3&page_size=abc",
        q(search="m7-weird"),
        q(page_size="+3"),
        q(page="\u0663"),
        q(page_size="\u0663"),
        q(inherited="true"),
        "?" + "&".join(["x=1"] * 1001),
    ]
    cases = [(base + suffix) for suffix in lists]
    for role in roles:
        cases.append(f"{base}{role['pk']}/")
    cases += [
        f"{base}{roles[0]['pk'].replace('-', '')}/",
        f"{base}urn:uuid:{roles[0]['pk']}/",
        f"{base}{roles[0]['pk'][:-1]}g/",
        f"{base}{roles[0]['pk']}/{q(users=999999)}",
        f"{base}{roles[0]['pk']}/{q(managed='bogus')}",
        f"{base}00000000-0000-0000-0000-000000000000/",
        f"{base}not-a-uuid/",
        f"{base}{roles[0]['pk']}/{q(search='zzz-no-match')}",
        f"{base}{roles[0]['pk']}/{q(page='abc')}",
        f"{base}{roles[0]['pk'].upper()}/",
    ]
    return cases


ENDPOINTS = {"rbac_roles": role_cases}


def strip_trace(response):
    status, headers, body = response
    headers = {k: v for k, v in headers.items() if k != TRACE}
    return status, headers, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=None)
    ap.add_argument("--only", default=None, help="comma-separated endpoint names")
    args = ap.parse_args()

    tokens = [None, "not-a-token", "m7-expired", "m7-recovery"] + [f"m7-{s}" for s in SUBJECTS]
    results, served = [], {}
    for name, make in ENDPOINTS.items():
        if args.only and name not in args.only.split(","):
            continue
        for path in make():
            for token in tokens:
                ref = harness.fetch(REF, path, token)
                ref2 = harness.fetch(REF2, path, token)
                cand = harness.fetch(CAND, path, token)
                rust = TRACE in cand[1]
                served[name] = served.get(name, 0) + int(rust)
                cand = strip_trace(cand)
                diffs = harness.compare(ref, cand)
                noise = harness.compare(ref, ref2)
                noise_kinds = {harness.kind(d) for d in noise}
                if not diffs:
                    bucket = "equal"
                elif all(harness.kind(d) in noise_kinds for d in diffs):
                    bucket = "nondeterministic"
                else:
                    bucket = "different"
                results.append(
                    {
                        "endpoint": name,
                        "path": path,
                        "token": token,
                        "status": ref[0],
                        "rust": rust,
                        "bucket": bucket,
                        "diffs": diffs,
                    }
                )
                if bucket == "different":
                    print(f"DIFF {token} {path}: " + "; ".join(diffs)[:600])

    buckets, statuses = {}, {}
    for r in results:
        buckets[r["bucket"]] = buckets.get(r["bucket"], 0) + 1
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    summary = {
        "cases": len(results),
        "buckets": dict(sorted(buckets.items())),
        "served_by_rust": served,
        "reference_status_histogram": dict(sorted(statuses.items())),
    }
    print(json.dumps(summary))
    if args.report:
        pathlib.Path(args.report).write_text(
            json.dumps({"summary": summary, "results": results}, indent=1) + "\n"
        )
    sys.exit(1 if buckets.get("different") else 0)


if __name__ == "__main__":
    main()
