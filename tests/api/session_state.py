# Compares the moved sessions after their save (tests/api/run.sh): Django's
# rows (ref) against Rust's (cand). `last_ip` and `expiring` must be equal,
# `expires` within a few seconds (both are now + the session age), and
# `session_data` equal once unpickled. CPython does not pickle these
# sessions deterministically, so the bytes themselves are not compared.
# Reads {"ref": rows, "cand": rows} on stdin; run with `manage shell -c`.
import base64
import json
import pickle
import sys


def norm(value, path=()):
    """A comparable form: containers and object attributes, recursively
    (Django's `_state` excluded). A reference back to an object on the
    current path becomes its position on that path, so cycles compare too."""
    if id(value) in path:
        return ("<cycle>", path.index(id(value)))
    if isinstance(value, (dict, list, tuple)) or hasattr(value, "__dict__"):
        path = (*path, id(value))
    if isinstance(value, dict):
        return {repr(k): norm(v, path) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [norm(v, path) for v in value]
    if hasattr(value, "__dict__"):
        state = {k: norm(v, path) for k, v in vars(value).items() if k != "_state"}
        return {"__class__": type(value).__qualname__, "state": state}
    return repr(value)


sys.setrecursionlimit(20000)
data = json.load(sys.stdin)
ref = {r["key"]: r for r in data["ref"] or []}
cand = {r["key"]: r for r in data["cand"] or []}
ok = set(ref) == set(cand) and len(ref) == 3
for key in ref:
    a, b = ref[key], cand.get(key, {})
    same = (
        a["last_ip"] == b.get("last_ip")
        and a["expiring"] == b.get("expiring")
        and abs(a["expires"] - b.get("expires", 0)) < 30
        and norm(pickle.loads(base64.b64decode(a["data"])))
        == norm(pickle.loads(base64.b64decode(b.get("data", ""))))
    )
    print(f"[session-state] {key[:8]} last_ip={a['last_ip']}/{b.get('last_ip')} equal={same}")
    ok = ok and same
print(f"[session-state] {'ok' if ok else 'MISMATCH'}")
if not ok:
    sys.exit(1)
