#!/usr/bin/env python3
"""Forwarded-header differential, observed on the Django side.

The front server decides, from the peer address and `listen.trusted_proxy_cidrs`,
which forwarding headers to trust (gorilla `ProxyHeaders`, `X-Forwarded-For`,
and mTLS headers) before Django sees the request. Responses rarely show the
result, but Django logs every request with the client IP it resolved,
the scheme, and the host. Each case here gets a unique `fwdcase` query
parameter; after sending it to all three stacks, this reads the `authentik.asgi`
log line for that path from each container and compares those fields. A
field that also differs between ref and ref2 is noise.

Run by run.sh after harness.py. Standard library only.
"""

import json
import subprocess
import sys
import time
import urllib.error
import urllib.request

STACKS = {
    "ref": ("http://127.0.0.1:29000", "ak-diff-ref-1"),
    "ref2": ("http://127.0.0.1:29200", "ak-diff-ref2-1"),
    "cand": ("http://127.0.0.1:29100", "ak-diff-cand-1"),
}
HOST = "authentik.test"
FIELDS = ("remote", "scheme", "host", "domain_url", "user_agent", "status", "method")

CASES = [
    {},
    {"X-Forwarded-For": "1.2.3.4"},
    {"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
    {"X-Forwarded-For": "not-an-ip"},
    {"X-Forwarded-For": "2001:db8::1"},
    {"X-Real-IP": "9.9.9.9"},
    {"X-Real-IP": "9.9.9.9", "X-Forwarded-For": "1.2.3.4"},
    {"Forwarded": "for=8.8.8.8;proto=https;host=fwd.test"},
    {"Forwarded": 'for="[2001:db8::2]:4711"'},
    {"Forwarded": "for=8.8.8.8, for=7.7.7.7"},
    {"X-Forwarded-Proto": "https"},
    {"X-Forwarded-Proto": "HTTPS"},
    {"X-Forwarded-Proto": "ftp"},
    {"X-Forwarded-Scheme": "https"},
    {"X-Forwarded-Host": "other.test"},
    {"X-Forwarded-Host": "other.test, more.test"},
    {"X-Forwarded-Host": "other.test", "X-Forwarded-Proto": "https", "X-Forwarded-For": "1.2.3.4"},
    {"X-Authentik-Remote-IP": "6.6.6.6"},
    {"SSL-Client-Cert": "abc", "X-Forwarded-Client-Cert": "def"},
    {"User-Agent": ""},
    {"User-Agent": "diff-agent/1.0"},
]


def send(base, path, headers):
    req = urllib.request.Request(base + path, headers={"Host": HOST, "Accept": "application/json", **headers})
    if headers.get("User-Agent") == "":
        req.remove_header("User-agent")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            resp.read()
            return resp.status
    except urllib.error.HTTPError as err:
        err.read()
        return err.code


def django_lines(container, since):
    out = subprocess.run(
        ["docker", "logs", "--since", since, container], capture_output=True, text=True, check=True
    )
    lines = {}
    for raw in (out.stdout + out.stderr).splitlines():
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        if entry.get("logger") == "authentik.asgi" and "fwdcase=" in str(entry.get("event", "")):
            lines[entry["event"]] = {k: entry.get(k) for k in FIELDS}
    return lines


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "trusted"
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 2))
    paths = []
    statuses = {}
    for i, headers in enumerate(CASES):
        path = f"/api/v3/root/config/?fwdcase={mode}-{i}"
        paths.append((path, headers))
        statuses[path] = {name: send(base, path, headers) for name, (base, _) in STACKS.items()}
    time.sleep(2)
    seen = {name: django_lines(container, since) for name, (_, container) in STACKS.items()}

    different, noise, missing = [], [], []
    for path, headers in paths:
        if statuses[path]["ref"] != statuses[path]["cand"]:
            different.append(f"{path} {headers}: HTTP status {statuses[path]['ref']} != {statuses[path]['cand']}")
        rows = {name: seen[name].get(path) for name in STACKS}
        if not any(rows.values()):
            continue  # Django logged none of them (e.g. DisallowedHost): agreement
        if not all(rows.values()):
            missing.append(f"{path} {headers}: no Django log line in {[n for n, r in rows.items() if not r]}")
            continue
        noisy = {f for f in FIELDS if rows["ref"][f] != rows["ref2"][f]}
        for field in FIELDS:
            if rows["ref"][field] != rows["cand"][field]:
                line = f"{path} {headers}: {field} {rows['ref'][field]!r} != {rows['cand'][field]!r}"
                (noise if field in noisy else different).append(line)
    # Self-check that the mode is in effect: a trusted peer's X-Forwarded-For
    # becomes Django's client IP, an untrusted peer's does not.
    probe = seen["ref"].get(f"/api/v3/root/config/?fwdcase={mode}-1", {})
    if (probe.get("remote") == "1.2.3.4") != (mode == "trusted"):
        sys.exit(f"mode self-check failed: {mode} but reference resolved {probe.get('remote')!r}")
    for line in different:
        print("DIFF " + line)
    for line in missing:
        print("MISSING " + line)
    print(json.dumps({"mode": mode, "cases": len(CASES), "different": len(different), "noise": len(noise), "missing": len(missing)}))
    sys.exit(1 if different or missing else 0)


if __name__ == "__main__":
    main()
