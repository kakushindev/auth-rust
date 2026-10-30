#!/usr/bin/env python3
"""Embedded outpost differential, observed on the Django side: the set of
requests the embedded outpost makes to core (path, client IP and host as
Django resolves them, scheme, user agent, authentication, status), from each
server container's `authentik.asgi` log. Counts are timing and are not
compared. Usage: outpost_requests.py REF_CONTAINER CAND_CONTAINER"""

import json
import subprocess
import sys


def requests(container):
    out = subprocess.run(["docker", "logs", container], capture_output=True, text=True, check=True)
    seen = set()
    for raw in (out.stdout + out.stderr).splitlines():
        try:
            entry = json.loads(raw)
        except ValueError:
            continue
        agent = str(entry.get("user_agent", ""))
        if entry.get("logger") != "authentik.asgi" or not agent.startswith("goauthentik.io/outpost/"):
            continue
        path = str(entry.get("event")).split("?")[0]
        if path.startswith("/ws/outpost/"):
            path = "/ws/outpost/<pk>/"
        seen.add((path, entry.get("remote"), entry.get("host"), entry.get("scheme"), agent,
                  entry.get("auth_via"), entry.get("status")))
    return seen


def main():
    ref, cand = requests(sys.argv[1]), requests(sys.argv[2])
    for row in sorted(ref | cand, key=str):
        mark = "  " if row in ref and row in cand else ("- " if row in ref else "+ ")
        print(mark + str(row))
    print("embedded outpost requests: " + ("identical" if ref == cand else "DIFFERENT"))
    sys.exit(0 if ref == cand else 1)


if __name__ == "__main__":
    main()
