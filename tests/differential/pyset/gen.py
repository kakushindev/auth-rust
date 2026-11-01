"""Iteration orders of CPython int sets as Django's m2m `_add_items` builds
them: `target_ids = set(); target_ids.add(x)` per object, then
`target_ids.difference(<queryset>)` (a non-set iterable, so a copy and
discards). Run with the reference image's Python; prints JSON vectors.
"""

import json
import random
import sys

rng = random.Random(20261101)
cases = []
shapes = [(0, 0), (1, 0), (3, 1), (5, 0), (5, 2), (8, 3), (11, 0), (17, 5), (33, 0), (40, 12), (64, 20), (90, 30)]
for n, k in shapes:
    for spread in (16, 64, 800, 5000, 2**40):
        for _ in range(4):
            objs = [rng.randint(1, spread) for _ in range(n)]
            if objs and rng.random() < 0.5:
                objs += rng.sample(objs, min(len(objs), 3))
            existing = rng.sample(objs, min(k, len(objs))) + [rng.randint(1, spread) for _ in range(2)]
            target = set()
            for x in objs:
                target.add(x)
            cases.append({"objs": objs, "existing": existing, "order": list(target.difference(existing))})
for _ in range(50):
    objs = [rng.choice([-1, -2, 0, 2**61 - 1, 2**61, 2**63 - 1, -(2**63), rng.randint(-50, 50)]) for _ in range(rng.randint(1, 20))]
    target = set()
    for x in objs:
        target.add(x)
    existing = objs[:2]
    cases.append({"objs": objs, "existing": existing, "order": list(target.difference(existing))})
json.dump({"python": sys.version, "cases": cases}, sys.stdout)
