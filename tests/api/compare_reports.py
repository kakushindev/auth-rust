"""Compare two tests/api/run.sh reports case by case.

Usage: compare_reports.py BASELINE.json NEW.json

A faster way to run the differential is only acceptable if it decides
what the slower run decided: the same cases, and for each one the same
reference status and whether Rust served it, with no case "different". A
case may move between "equal" and "nondeterministic" only because its
noise is random per run (`users/me/`); those moves are listed. Exits
non-zero on any real difference.
"""

import json
import re
import sys


UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32}", re.I)


def load(path):
    """Cases keyed by endpoint, token and position: rows the fixture creates
    have fresh primary keys whenever it is rebuilt, so paths differ between
    fixtures while the suite's order does not. The path, with UUIDs masked,
    is kept as a check that positions line up."""
    results = json.load(open(path))["results"]
    out, seen = {}, {}
    for r in results:
        n = seen[(r["endpoint"], r["token"])] = seen.get((r["endpoint"], r["token"]), -1) + 1
        key = (r["endpoint"], r["token"], n)
        out[key] = [(UUID.sub("<uuid>", r["path"]), r["status"], r["bucket"], r["rust"])]
    return out


base, new = load(sys.argv[1]), load(sys.argv[2])
problems, moves = [], []
for key in sorted(set(base) | set(new), key=str):
    a, b = sorted(base.get(key, [])), sorted(new.get(key, []))
    if a == b:
        continue
    strip = lambda rows: sorted((path, status, rust) for path, status, _, rust in rows)
    buckets = {bucket for _, _, bucket, _ in a + b}
    if strip(a) == strip(b) and buckets <= {"equal", "nondeterministic"}:
        moves.append(f"{key}: {a} -> {b}")
    else:
        problems.append(f"{key}: baseline {a} != new {b}")
different = [k for k, rows in new.items() if any(bucket == "different" for _, _, bucket, _ in rows)]
problems += [f"{k}: different in the new run" for k in different if not any(str(k) in p for p in problems)]
print(
    f"[compare] {sum(len(v) for v in base.values())} baseline cases, {sum(len(v) for v in new.values())} new, "
    f"{len(problems)} differ, {len(moves)} equal<->nondeterministic moves"
)
for p in problems[:40]:
    print("  DIFF " + p)
for m in moves[:20]:
    print("  move " + m)
sys.exit(1 if problems else 0)
