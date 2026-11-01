#!/usr/bin/env python3
"""M8 write differential: the same write requests against reference, second
reference (noise floor) and candidate, comparing the responses *and* every
row the request changed (capture.sql's m8cap.changes), case by case and in
order. Writes change state, so cases run sequentially and identically on
every stack.

Normalization is narrow:
- A UUID or 32-hex value is replaced by a placeholder only when it is fresh:
  absent from that stack's database when the suite started (its pg_dump).
  Placeholders are numbered per stack in order of first appearance over the
  whole run, so a value created in one case and referenced in a later one
  keeps its number. A wrong reference to a fixture row is therefore a
  literal mismatch, and to another created row a number mismatch.
- Timestamps at or after the case's start become `<now>`. Older ones (the
  fixture's) stay literal.
- `bytea` task messages become `<bytea>`: they embed a random message id and
  timestamp, and tests/events/check_enqueue.py checks them byte for byte.

Standard library only; the databases are read through `docker exec psql`.
"""

import argparse
import concurrent.futures
import datetime
import json
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[2]
STACKS = {
    "ref": ("http://127.0.0.1:29000", "ak-api-ref-db-1"),
    "ref2": ("http://127.0.0.1:29200", "ak-api-ref2-db-1"),
    "cand": ("http://127.0.0.1:29100", "ak-api-cand-db-1"),
}
HOST = "authentik.test"
TRACE = "x-authentik-rs"
ADMIN = "m7-akadmin"
# Per-request values: compared for presence only.
NORMALIZED_HEADERS = {"date", "x-authentik-id", "x-request-id"}
IGNORED_HEADERS = {"server", TRACE}

UUID_RE = re.compile(r"\b[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}\b", re.I)
TS_RE = re.compile(r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d(?::?\d\d)?)\b")
BYTEA_RE = re.compile(r"^\\x[0-9a-f]*$")


class Psql:
    """One long-lived `psql` per database: a `docker exec` per query costs
    about 90 ms, a query on an open session about 4 ms."""

    END = "__m8end__"

    def __init__(self, container):
        self.proc = subprocess.Popen(
            ["docker", "exec", "-i", container, "psql", "-U", "authentik", "-d", "authentik", "-At", "-q", "-v", "ON_ERROR_STOP=1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
        )

    def query(self, sql):
        self.proc.stdin.write(sql + f"\n\\echo {self.END}\n")
        self.proc.stdin.flush()
        out = []
        while True:
            line = self.proc.stdout.readline()
            if not line:
                sys.exit(f"psql exited ({self.proc.wait()}) on: {sql}")
            if line.rstrip("\n") == self.END:
                return "\n".join(out)
            out.append(line.rstrip("\n"))


SESSIONS = {}


def psql(container, sql):
    if container not in SESSIONS:
        SESSIONS[container] = Psql(container)
    return SESSIONS[container].query(sql)


def preexisting(container):
    """Every UUID-like literal in the stack's data before the suite."""
    dump = subprocess.run(
        ["docker", "exec", container, "pg_dump", "-U", "authentik", "-d", "authentik", "--data-only", "-n", "public"],
        capture_output=True, text=True, check=True,
    ).stdout
    return {m.group(0).lower().replace("-", "") for m in UUID_RE.finditer(dump)}


# Writers that run beside the request, not because of it: the embedded
# outpost's state heartbeat, and the reference's Go server polling the
# brands API over IPC (COMPATIBILITY_REPORT, "Brand TLS polling"). When
# that poll fails, Django records a `system_exception` event with its
# dispatch task and log, on the references only.
BACKGROUND = [("django_postgres_cache_cacheentry", "goauthentik.io/outposts/state/")]
IPC_AGENT = "goauthentik.io/ipc/"


def encode_long(n):
    """`pickle.encode_long`: little-endian two's complement, minimal."""
    return n.to_bytes((n.bit_length() + 8) // 8, "little", signed=True)


def background_rows(changes):
    """Indexes of `changes` that no case request wrote."""
    out = set()
    for i, c in enumerate(changes):
        row = c["new"] or c["old"] or {}
        if any(c["tbl"] == t and prefix in str(row.get("cache_key", "")) for t, prefix in BACKGROUND):
            out.add(i)
    events = {}
    for i, c in enumerate(changes):
        row = c["new"] or {}
        http = ((row.get("context") or {}).get("http_request") or {}) if c["tbl"] == "authentik_events_event" else {}
        if str(http.get("user_agent", "")).startswith(IPC_AGENT):
            out.add(i)
            events[uuid.UUID(row["event_uuid"])] = i
    # `event_trigger_dispatch(event_uuid)`: the pickled UUID's `int`.
    tasks = set()
    for i, c in enumerate(changes):
        row = c["new"] or c["old"] or {}
        if c["tbl"] != "authentik_tasks_task" or not str(row.get("message", "")).startswith("\\x"):
            continue
        message = bytes.fromhex(row["message"][2:])
        if any(encode_long(u.int) in message for u in events):
            out.add(i)
            tasks.add(row["message_id"])
    for i, c in enumerate(changes):
        row = c["new"] or c["old"] or {}
        if c["tbl"] == "authentik_tasks_tasklog" and row.get("task_id") in tasks:
            out.add(i)
    return out


def take_changes(container):
    rows = psql(container, (
        "WITH d AS (DELETE FROM m8cap.changes RETURNING *) "
        "SELECT coalesce(json_agg(json_build_object('tbl', tbl, 'op', op, 'old', old, 'new', new) ORDER BY id), '[]') FROM d;"
    ))
    changes = json.loads(rows.strip() or "[]")
    skip = background_rows(changes)
    return [c for i, c in enumerate(changes) if i not in skip]


def request(base, method, path, token, body, content_type):
    data = None
    headers = {"Accept": "application/json", "Host": HOST}
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        headers["Content-Type"] = content_type
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        resp = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as err:
        resp = err
    raw = resp.read()
    headers = {}
    for k, v in resp.headers.items():
        headers.setdefault(k.lower(), []).append(v)
    try:
        payload = json.loads(raw) if raw else None
    except ValueError:
        payload = raw.decode("utf-8", "replace")
    return resp.status, headers, payload


class Normalizer:
    def __init__(self, known):
        self.known = known
        self.names = {}

    def placeholder(self, value):
        key = value.lower().replace("-", "")
        if key in self.known:
            return value
        if key not in self.names:
            self.names[key] = f"<id{len(self.names)}>"
        return self.names[key]

    def text(self, s, since):
        if BYTEA_RE.match(s):
            return "<bytea>"

        def ts(m):
            text = m.group(0).replace(" ", "T").replace("Z", "+00:00")
            if re.search(r"[+-]\d\d$", text):
                text += ":00"
            try:
                when = datetime.datetime.fromisoformat(text)
            except ValueError:
                return m.group(0)
            return "<now>" if when.timestamp() >= since else m.group(0)

        s = TS_RE.sub(ts, s)
        return UUID_RE.sub(lambda m: self.placeholder(m.group(0)), s)

    def walk(self, value, since):
        if isinstance(value, dict):
            return {self.text(k, since): self.walk(v, since) for k, v in value.items()}
        if isinstance(value, list):
            return [self.walk(v, since) for v in value]
        if isinstance(value, str):
            return self.text(value, since)
        return value


def resolve(base, path):
    """`{role:NAME}`, `{notification:BODY}` → that row's pk on this stack."""

    def one(m):
        kind, name = m.group(1), m.group(2)
        lookup = {
            "role": "/api/v3/rbac/roles/?name=",
            "notification": "/api/v3/events/notifications/?body=",
            "initial": "/api/v3/rbac/initial_permissions/?name=",
        }[kind]
        _, _, body = request(base, "GET", lookup + urllib.parse.quote(name), ADMIN, None, None)
        results = body["results"]
        return str(results[0]["pk"]) if results else "00000000-0000-4000-8000-000000000000"

    return re.sub(r"\{(\w+):([^}]+)\}", one, path)


def resolve_body(base, body):
    """`resolve` on every string of a JSON body."""
    if isinstance(body, dict):
        return {k: resolve_body(base, v) for k, v in body.items()}
    if isinstance(body, list):
        return [resolve_body(base, v) for v in body]
    if isinstance(body, str):
        return resolve(base, body)
    return body


import urllib.parse  # noqa: E402

JSON = "application/json"


def groups():
    """Self-contained case groups, in run order: each needs only the fixture
    and its own earlier cases, so `--only` can run any of them alone."""
    return {
        "roles": role_cases(),
        "notifications": notification_cases(),
        "initial_permissions": initial_permission_cases(),
    }


def role_cases():
    """(name, method, path, token, body, content type), in run order."""
    roles = "/api/v3/rbac/roles/"
    return [
        ("create", "POST", roles, ADMIN, {"name": "m8-role-a"}, JSON),
        ("create duplicate", "POST", roles, ADMIN, {"name": "m8-role-a"}, JSON),
        ("create blank", "POST", roles, ADMIN, {"name": ""}, JSON),
        ("create missing", "POST", roles, ADMIN, {}, JSON),
        ("create null", "POST", roles, ADMIN, {"name": None}, JSON),
        ("create wrong type", "POST", roles, ADMIN, {"name": ["x"]}, JSON),
        ("create invalid json", "POST", roles, ADMIN, b'{"name": ', JSON),
        ("create form", "POST", roles, ADMIN, b"name=m8-role-form", "application/x-www-form-urlencoded"),
        ("create unicode", "POST", roles, ADMIN, {"name": "m8-r\u00f6le \U0001f600"}, JSON),
        ("create extra fields", "POST", roles, ADMIN, {"name": "m8-role-extra", "pk": "x", "managed": "y"}, JSON),
        ("create anonymous", "POST", roles, None, {"name": "m8-role-anon"}, JSON),
        ("create no permission", "POST", roles, "m7-m6-none", {"name": "m8-role-none"}, JSON),
        ("create model permission", "POST", roles, "m7-m6-direct", {"name": "m8-role-direct"}, JSON),
        ("create integer", "POST", roles, ADMIN, {"name": 5}, JSON),
        ("create bool", "POST", roles, ADMIN, {"name": True}, JSON),
        ("create trimmed", "POST", roles, ADMIN, {"name": "  m8-role-trim\t"}, JSON),
        ("create trimmed duplicate", "POST", roles, ADMIN, {"name": "m8-role-trim "}, JSON),
        ("create whitespace", "POST", roles, ADMIN, {"name": " \n "}, JSON),
        ("create array body", "POST", roles, ADMIN, [{"name": "m8-role-list"}], JSON),
        ("create charset", "POST", roles, ADMIN, {"name": "m8-role-charset"}, JSON + "; charset=utf-8"),
        ("create repeated key", "POST", roles, ADMIN, b'{"name": "m8-role-first", "name": "m8-role-last"}', JSON),
        ("patch rename", "PATCH", roles + "{role:m8-role-a}/", ADMIN, {"name": "m8-role-b"}, JSON),
        ("patch same", "PATCH", roles + "{role:m8-role-b}/", ADMIN, {"name": "m8-role-b"}, JSON),
        ("patch duplicate", "PATCH", roles + "{role:m8-role-b}/", ADMIN, {"name": "m8-role-extra"}, JSON),
        ("put", "PUT", roles + "{role:m8-role-b}/", ADMIN, {"name": "m8-role-c"}, JSON),
        ("put missing", "PUT", roles + "{role:m8-role-c}/", ADMIN, {}, JSON),
        ("patch no permission", "PATCH", roles + "{role:m8-role-c}/", "m7-m6-none", {"name": "x"}, JSON),
        ("patch missing role", "PATCH", roles + "00000000-0000-4000-8000-000000000000/", ADMIN, {"name": "x"}, JSON),
        ("patch invalid pk", "PATCH", roles + "not-a-uuid/", ADMIN, {"name": "x"}, JSON),
        ("patch anonymous", "PATCH", roles + "{role:m8-role-c}/", None, {"name": "x"}, JSON),
        ("patch empty", "PATCH", roles + "{role:m8-role-c}/", ADMIN, {}, JSON),
        ("patch blank", "PATCH", roles + "{role:m8-role-c}/", ADMIN, {"name": ""}, JSON),
        ("patch form", "PATCH", roles + "{role:m8-role-c}/", ADMIN, b"name=y", "application/x-www-form-urlencoded"),
        ("patch model permission", "PATCH", roles + "{role:m8-role-c}/", "m7-m6-direct", {"name": "m8-role-c"}, JSON),
        ("put extra fields", "PUT", roles + "{role:m8-role-c}/", ADMIN, {"name": "m8-role-c", "managed": "z"}, JSON),
        ("delete anonymous", "DELETE", roles + "{role:m8-role-c}/", None, None, None),
        ("delete", "DELETE", roles + "{role:m8-role-c}/", ADMIN, None, None),
        ("delete again", "DELETE", roles + "{role:m8-role-c}/", ADMIN, None, None),
        ("delete with members", "DELETE", roles + "{role:m6-dup-a}/", ADMIN, None, None),
        ("delete no permission", "DELETE", roles + "{role:m6-model}/", "m7-m6-none", None, None),
        ("delete model permission", "DELETE", roles + "{role:5}/", "m7-m6-direct", None, None),
        ("delete with permissions", "DELETE", roles + "{role:m6-model}/", ADMIN, None, None),
        ("delete created", "DELETE", roles + "{role:m8-role-trim}/", ADMIN, None, None),
    ]


def notification_cases():
    """The fixture's notifications (tests/api/populate.py): n0 and n1 are
    akadmin's, n2 (unseen, with an event) and n3 m6-direct's."""
    base = "/api/v3/events/notifications/"
    n0, n1, n2, n3 = (base + "{notification:m7 body %d \"q\"}/" % i for i in range(4))
    owner, other = "m7-m6-direct", "m7-m6-none"
    seen = base + "mark_all_seen/"
    return [
        ("notification patch owner", "PATCH", n2, owner, {"seen": True}, JSON),
        ("notification patch other owner", "PATCH", n1, owner, {"seen": False}, JSON),
        ("notification patch no permission", "PATCH", n2, other, {"seen": False}, JSON),
        ("notification patch anonymous", "PATCH", n2, None, {"seen": False}, JSON),
        ("notification patch fields", "PATCH", n0, ADMIN, {"hyperlink": "  https://x.test/ ", "hyperlink_label": None, "seen": "no"}, JSON),
        ("notification patch blank", "PATCH", n0, ADMIN, {"hyperlink": "", "hyperlink_label": "   "}, JSON),
        ("notification patch errors", "PATCH", n0, ADMIN, {"hyperlink": "x" * 4097, "hyperlink_label": 5, "seen": "maybe"}, JSON),
        ("notification patch types", "PATCH", n0, ADMIN, {"hyperlink": [1], "hyperlink_label": True, "seen": [True]}, JSON),
        ("notification patch null seen", "PATCH", n0, ADMIN, {"seen": None}, JSON),
        ("notification patch float seen", "PATCH", n0, ADMIN, {"seen": 1.0}, JSON),
        ("notification patch fraction seen", "PATCH", n0, ADMIN, {"seen": 0.5}, JSON),
        ("notification patch integer seen", "PATCH", n0, ADMIN, {"seen": 0}, JSON),
        ("notification patch upper seen", "PATCH", n0, ADMIN, {"seen": "TRUE", "hyperlink_label": 7}, JSON),
        ("notification patch mixed seen", "PATCH", n0, ADMIN, {"seen": "oFf"}, JSON),
        ("notification patch max length", "PATCH", n0, ADMIN, {"hyperlink": "\u00e9" * 4096}, JSON),
        ("notification patch event", "PATCH", n0, ADMIN, {"event": None}, JSON),
        ("notification patch form", "PATCH", n0, ADMIN, b"seen=true", "application/x-www-form-urlencoded"),
        ("notification put read-only", "PUT", n3, owner, {"seen": False, "hyperlink": "h", "pk": "x", "body": "changed", "severity": "alert"}, JSON),
        ("notification put empty", "PUT", n3, owner, {}, JSON),
        ("notification patch missing", "PATCH", base + "00000000-0000-4000-8000-000000000000/", ADMIN, {}, JSON),
        ("notification patch invalid pk", "PATCH", base + "nope/", ADMIN, {}, JSON),
        ("mark all seen", "POST", seen, owner, None, None),
        ("mark all seen again", "POST", seen, owner, None, None),
        ("mark all seen anonymous", "POST", seen, None, None, None),
        ("mark all seen form body", "POST", seen, ADMIN, b"x=1", "application/x-www-form-urlencoded"),
        ("mark all seen get", "GET", seen, ADMIN, None, None),
        ("mark all seen put", "PUT", seen, ADMIN, {}, JSON),
        ("notification delete other owner", "DELETE", n1, owner, None, None),
        ("notification delete owner", "DELETE", n3, owner, None, None),
        ("notification delete again", "DELETE", n3, owner, None, None),
        ("notification delete invalid pk", "DELETE", base + "nope/", ADMIN, None, None),
        ("notification delete admin", "DELETE", n1, ADMIN, None, None),
    ]



def initial_permission_cases():
    """InitialPermissions on a role nobody holds (so no request's own
    initial permissions apply). Permission ids are the fixture's serial
    ids; the larger lists exercise CPython's set order for the m2m rows."""
    base = "/api/v3/rbac/initial_permissions/"
    roles = "/api/v3/rbac/roles/"
    role = "{role:m8-ip-role}"
    a, b = base + "{initial:m8-ip-a}/", base + "{initial:m8-ip-b}/"
    many = [700, 9, 8, 300, 17, 1, 64, 33, 2, 500, 129, 9, 700]
    return [
        ("ip role", "POST", roles, ADMIN, {"name": "m8-ip-role"}, JSON),
        ("ip create", "POST", base, ADMIN, {"name": "m8-ip-a", "role": role, "permissions": [3, 1, 2]}, JSON),
        ("ip create many", "POST", base, ADMIN, {"name": "m8-ip-b", "role": role, "permissions": many}, JSON),
        ("ip create no permissions key", "POST", base, ADMIN, {"name": "m8-ip-c", "role": role}, JSON),
        ("ip create empty permissions", "POST", base, ADMIN, {"name": "m8-ip-d", "role": role, "permissions": []}, JSON),
        ("ip create duplicate", "POST", base, ADMIN, {"name": "m8-ip-a", "role": role}, JSON),
        ("ip create long name", "POST", base, ADMIN, {"name": "x" * 151, "role": role}, JSON),
        ("ip create max name", "POST", base, ADMIN, {"name": "y" * 150, "role": role}, JSON),
        ("ip create missing role", "POST", base, ADMIN, {"name": "m8-ip-e"}, JSON),
        ("ip create null role", "POST", base, ADMIN, {"name": "m8-ip-e", "role": None}, JSON),
        ("ip create invalid role", "POST", base, ADMIN, {"name": "m8-ip-e", "role": "nope"}, JSON),
        ("ip create unknown role", "POST", base, ADMIN, {"name": "m8-ip-e", "role": "00000000-0000-4000-8000-000000000000"}, JSON),
        ("ip create integer role", "POST", base, ADMIN, {"name": "m8-ip-e", "role": 5}, JSON),
        ("ip create negative role", "POST", base, ADMIN, {"name": "m8-ip-e", "role": -5}, JSON),
        ("ip create bool role", "POST", base, ADMIN, {"name": "m8-ip-e", "role": True}, JSON),
        ("ip create list role", "POST", base, ADMIN, {"name": "m8-ip-e", "role": [role]}, JSON),
        ("ip create permissions string", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": "1"}, JSON),
        ("ip create permissions int", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": 1}, JSON),
        ("ip create permissions null", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": None}, JSON),
        ("ip create permission bool", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": [1, True]}, JSON),
        ("ip create permission null", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": [None]}, JSON),
        ("ip create permission text", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": ["abc"]}, JSON),
        ("ip create permission digits", "POST", base, ADMIN, {"name": "m8-ip-f", "role": role, "permissions": ["7", "007"]}, JSON),
        ("ip create permission unknown", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": [1, 999999]}, JSON),
        ("ip create permission huge", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": [99999999999]}, JSON),
        ("ip create permission list", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": [[1]]}, JSON),
        ("ip create permission dict", "POST", base, ADMIN, {"name": "m8-ip-e", "role": role, "permissions": [{"a": 1}]}, JSON),
        ("ip create several errors", "POST", base, ADMIN, {"name": "", "role": "nope", "permissions": "x"}, JSON),
        ("ip create anonymous", "POST", base, None, {"name": "m8-ip-e", "role": role}, JSON),
        ("ip create no permission", "POST", base, "m7-m6-none", {"name": "m8-ip-e", "role": role}, JSON),
        ("ip patch rename", "PATCH", a, ADMIN, {"name": "m8-ip-a2"}, JSON),
        ("ip patch same name", "PATCH", base + "{initial:m8-ip-a2}/", ADMIN, {"name": "m8-ip-a2"}, JSON),
        ("ip patch duplicate", "PATCH", base + "{initial:m8-ip-a2}/", ADMIN, {"name": "m8-ip-b"}, JSON),
        ("ip patch permissions overlap", "PATCH", b, ADMIN, {"permissions": [3, 4, 5, 700, 64, 100, 129]}, JSON),
        ("ip patch permissions repeated", "PATCH", b, ADMIN, {"permissions": [5, 5, 64, 3, 3]}, JSON),
        ("ip patch permissions clear", "PATCH", b, ADMIN, {"permissions": []}, JSON),
        ("ip patch permissions refill", "PATCH", b, ADMIN, {"permissions": many + [40, 72, 136, 264, 520]}, JSON),
        ("ip patch role", "PATCH", b, ADMIN, {"role": "{role:m6-object}"}, JSON),
        ("ip put", "PUT", b, ADMIN, {"name": "m8-ip-b", "role": role, "permissions": [2]}, JSON),
        ("ip put missing role", "PUT", b, ADMIN, {"name": "m8-ip-b"}, JSON),
        ("ip put without permissions", "PUT", b, ADMIN, {"name": "m8-ip-b", "role": role}, JSON),
        ("ip patch empty", "PATCH", b, ADMIN, {}, JSON),
        ("ip patch no permission", "PATCH", b, "m7-m6-none", {"name": "x"}, JSON),
        ("ip patch missing", "PATCH", base + "999999/", ADMIN, {}, JSON),
        ("ip patch invalid pk", "PATCH", base + "abc/", ADMIN, {}, JSON),
        ("ip delete", "DELETE", b, ADMIN, None, None),
        ("ip delete renamed", "DELETE", base + "{initial:m8-ip-a2}/", ADMIN, None, None),
        ("ip delete no permission", "DELETE", base + "{initial:m8-ip-f}/", "m7-m6-none", None, None),
        ("ip delete empty", "DELETE", base + "{initial:m8-ip-c}/", ADMIN, None, None),
        ("ip role delete", "DELETE", roles + "{role:m8-ip-role}/", ADMIN, None, None),
    ]

def self_test(results):
    """A seeded difference in a case's response or changes must be found;
    otherwise the comparison proves nothing and the run is void."""
    probe = next((r for r in results if r["bucket"] == "equal" and len(r["cand"]["changes"]) >= 2), None) or next(
        (r for r in results if r["bucket"] == "equal" and r["cand"]["changes"]), None
    )
    if probe is None:
        sys.exit("write differential self-test: no case with changes to seed")
    cand = probe["cand"]
    changes = cand["changes"]
    first = json.loads(json.dumps(changes))
    row = first[0]["new"] or first[0]["old"]
    row[next(iter(row))] = "SEEDED"
    text = json.dumps(changes)
    ids = sorted(set(re.findall(r"<id(\d+)>", text)), key=int)
    seeds = {
        "value": first,
        "dropped row": changes[:-1],
        **({"reordered": changes[::-1]} if len(changes) > 1 else {}),
        "status": None,
    }
    if ids:
        seeds["reference"] = json.loads(text.replace(f"<id{ids[0]}>", f"<id{int(ids[-1]) + 1}>", 1))
    for name, seeded in seeds.items():
        if name == "status":
            mutated = [cand["response"][0] + 1, *cand["response"][1:]]
            same = mutated == probe["ref"]["response"]
        else:
            same = seeded == probe["ref"]["changes"]
        if same:
            sys.exit(f"write differential self-test: seeded {name} difference not detected")
    print(f"[self-test] {len(seeds)} seeded differences detected on {probe['case']!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=None)
    ap.add_argument("--only", default=None, help="comma-separated case groups")
    args = ap.parse_args()
    all_groups = groups()
    chosen = args.only.split(",") if args.only else list(all_groups)
    unknown = [g for g in chosen if g not in all_groups]
    if unknown:
        sys.exit(f"unknown groups {unknown}; known: {list(all_groups)}")
    pool = concurrent.futures.ThreadPoolExecutor(len(STACKS))
    known = dict(zip(STACKS, pool.map(lambda db: preexisting(db), (db for _, db in STACKS.values()))))
    norm = {name: Normalizer(known[name]) for name in STACKS}
    results, buckets, served = [], {}, 0
    for name, method, path, token, body, ctype in (c for g in chosen for c in all_groups[g]):
        def run(stack):
            base, db = STACKS[stack]
            resolved = resolve(base, path)
            resolved_body = resolve_body(base, body)
            take_changes(db)
            since = time.time() - 2
            status, headers, payload = request(base, method, resolved, token, resolved_body, ctype)
            changes = take_changes(db)
            rust = TRACE in headers
            headers = {
                k: (["<normalized>"] * len(v) if k in NORMALIZED_HEADERS else v)
                for k, v in headers.items()
                if k not in IGNORED_HEADERS
            }
            return {
                "rust": rust,
                "response": norm[stack].walk([status, headers, payload], since),
                "changes": norm[stack].walk(changes, since),
            }

        # The stacks run each case at once; each still sees every case in
        # order, and its own normalizer numbers its fresh values.
        out = dict(zip(STACKS, pool.map(run, STACKS)))
        diffs = [k for k in ("response", "changes") if out["ref"][k] != out["cand"][k]]
        noise = [k for k in ("response", "changes") if out["ref"][k] != out["ref2"][k]]
        bucket = "equal" if not diffs else ("nondeterministic" if set(diffs) <= set(noise) else "different")
        buckets[bucket] = buckets.get(bucket, 0) + 1
        served += out["cand"]["rust"]
        results.append({"case": name, "bucket": bucket, "diffs": diffs, "rust": out["cand"]["rust"], **out})
        if bucket == "different":
            print(f"DIFF {name}: {diffs}", flush=True)
    self_test(results)
    summary = {"cases": len(results), "buckets": buckets, "served_by_rust": served}
    print(json.dumps(summary))
    if args.report:
        pathlib.Path(args.report).write_text(json.dumps({"summary": summary, "results": results}, indent=1) + "\n")
    sys.exit(1 if buckets.get("different") else 0)


if __name__ == "__main__":
    main()
