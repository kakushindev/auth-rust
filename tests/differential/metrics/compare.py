#!/usr/bin/env python3
"""Metrics differential: compare listen.metrics (:9300) of two running
authentik server containers (reference Go vs candidate Rust).

Usage: compare.py REFERENCE_CONTAINER CANDIDATE_CONTAINER

Each container scrapes itself (the port is not published). Compared exactly:
status, headers (minus date), and the 404 bodies; per metric family the HELP
text, TYPE and label names; and the order of the front server's own (sorted)
families. Django's appended families are compared as a set, since their
order differs between two reference processes too. Values are runtime state
and are not compared. `go_*` families come from Go's runtime collector,
which has no Rust equivalent. They are listed, not counted as differences.
Standard library only.
"""

import json
import subprocess
import sys

PROBE = r"""
import json, urllib.request, urllib.error
out = {}
for path in ["/metrics", "/metrics/", "/", "/nope", "//metrics"]:
    req = urllib.request.Request("http://127.0.0.1:9300" + path)
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    try:
        r = urllib.request.build_opener(NoRedirect).open(req, timeout=60)
    except urllib.error.HTTPError as e:
        r = e
    body = r.read().decode("utf-8", "replace")
    out[path] = {"status": r.status, "headers": sorted((k.lower(), v) for k, v in r.headers.items() if k.lower() != "date"), "body": body}
print(json.dumps(out))
"""


def scrape(container):
    res = subprocess.run(
        ["docker", "exec", "-i", container, "python3", "-I", "-"],
        input=PROBE, capture_output=True, text=True, check=True,
    )
    return json.loads(res.stdout)


def families(text):
    """Ordered family name -> (help, type, label names)."""
    fams = {}
    current = None
    for line in text.splitlines():
        if line.startswith("# HELP "):
            name, _, help_ = line[7:].partition(" ")
            current = name
            fams.setdefault(name, {"help": help_, "type": None, "labels": set()})
        elif line.startswith("# TYPE "):
            name, _, kind = line[7:].partition(" ")
            current = name
            fams.setdefault(name, {"help": None, "type": kind, "labels": set()})["type"] = kind
        elif line and not line.startswith("#") and current:
            series = line.rsplit(" ", 1)[0]
            if "{" in series:
                for pair in series.split("{", 1)[1].rstrip("}").split('",'):
                    name = pair.split("=", 1)[0].strip(",")
                    if name:
                        fams[current]["labels"].add(name)
    return fams


def main():
    ref_name, cand_name = sys.argv[1:3]
    ref, cand = scrape(ref_name), scrape(cand_name)
    diffs = []
    for path in ref:
        r, c = ref[path], cand[path]
        if r["status"] != c["status"]:
            diffs.append(f"{path}: status {r['status']} != {c['status']}")
        rh = [h for h in r["headers"] if h[0] not in ("connection",)]
        ch = [h for h in c["headers"] if h[0] not in ("connection",)]
        if rh != ch:
            diffs.append(f"{path}: headers {rh} != {ch}")
        if path != "/metrics" and r["body"] != c["body"]:
            diffs.append(f"{path}: body {r['body'][:80]!r} != {c['body'][:80]!r}")
    rf, cf = families(ref["/metrics"]["body"]), families(cand["/metrics"]["body"])
    go_runtime = sorted(n for n in rf if n.startswith("go_"))
    for name in rf:
        if name.startswith("go_"):
            continue
        if name not in cf:
            diffs.append(f"family {name} only in reference")
            continue
        for key in ("help", "type", "labels"):
            if rf[name][key] != cf[name][key]:
                diffs.append(f"family {name} {key}: {rf[name][key]} != {cf[name][key]}")
    for name in cf:
        if name not in rf:
            diffs.append(f"family {name} only in candidate")
    # The front server's own families come first, sorted by name. Django's
    # appended families are ordered by its multiprocess collector, which
    # differs between two reference processes too, so they are compared as
    # a set (above).
    names_ref = [n for n in rf if not n.startswith("go_")]
    front = 1
    while front < len(names_ref) and names_ref[front - 1] < names_ref[front]:
        front += 1
    order_cand = [n for n in cf if n in rf and not n.startswith("go_")][:front]
    if names_ref[:front] != order_cand:
        diffs.append(f"front-server family order differs: {names_ref[:front]} != {order_cand}")
    print(json.dumps({
        "families_reference": len(rf),
        "families_compared": len([n for n in rf if not n.startswith("go_")]),
        "front_server_families": front,
        "go_runtime_families_not_emitted": len(go_runtime),
        "differences": diffs,
    }, indent=2))
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
