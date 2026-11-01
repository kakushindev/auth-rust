# Run with `python -m manage shell` after event_populate.py (run.sh).
"""Django's Event rows for Event.new(...).from_http(request, user), as JSON.

Each case is written in a savepoint rolled back afterwards. Recorded are the
case's inputs (for the Rust side to replay), the row as SQL reads it, and
the dramatiq tasks the event's post_save enqueued. Kwargs exercise
sanitize_dict and cleanse_dict; requests vary path, method, query string
(sensitive keys, a flow's wrapped `query`, percent escapes), user agent,
request id, client IP (ASN/GeoIP hits and misses, IPv6), brand, user,
override user, and sessions holding an impersonation or a flow plan with
a pending user.
"""

import json
import pickle
from itertools import product

from django.contrib.auth.models import AnonymousUser
from django.db import connection, transaction
from django.test import RequestFactory

from authentik.brands.models import Brand
from authentik.brands.utils import DEFAULT_BRAND
from authentik.core.models import User
from authentik.events.models import Event, EventAction
from authentik.flows.planner import FlowPlan
from authentik.tasks.models import Task, TaskLog

user = User.objects.get(username="m8-user")
other = User.objects.get(username="m8-other")
brand = Brand.objects.get(domain="m8.test")
default = Brand.objects.get(default=True)

KWARGS = [
    {},
    {"message": "hi"},
    {"password": "x", "token": "y", "nested": {"api_key": "k", "ok": "v", "auth_method": "pw", "passing": True}},
    {"lst": [0, "", None, "a", False, [], {}, 1, {"secret": "s"}, 0.0], "s": "a\u0000b", "n": 1.5, "big": 10**30,
     "neg": -1, "uni": "é€\U0001f642", "my_secret_list": ["a", {"x": "y"}, ["z"]]},
    {"password_change_date": "x", "auth_method_args": {"p": "1"}, "AUTH_METHOD": "m", "Passing": "p", "e": None},
]
REQUESTS = [
    None,
    {"method": "GET", "path": "/", "query": "", "ua": "", "rid": None},
    {"method": "POST", "path": "/api/v3/x/", "query": "a=1&token=t&b=%C3%A9&c+d=e+f&&x&y=&a=2&%FF=%zz",
     "ua": "Mozilla/5.0 é", "rid": "0123456789abcdef0123456789abcdef"},
    {"method": "GET", "path": "/if/flow/x/", "query": "query=next%3D%2Fx%26password%3Dp%26q%3D1", "ua": "ua",
     "rid": "r"},
]
IPS = ["8.8.8.8", "81.2.69.142", "10.0.0.1", "2001:DB8::1", "255.255.255.255", "::ffff:8.8.8.8"]
BRANDS = [None, "default", "m8", "fallback"]
USERS = [None, "anonymous", "user"]
OVERRIDES = [None, "other"]
SESSIONS = [None, "empty", "impersonation", "plan-other", "plan-same", "both"]


def user_obj(name):
    return {"anonymous": AnonymousUser(), "user": user, "other": other}[name]


def session_data(name):
    data = {}
    if name in ("impersonation", "both"):
        data["authentik/impersonate/original_user"] = other
        data["authentik/impersonate/user"] = user
    if name in ("plan-other", "plan-same", "both"):
        plan = FlowPlan(flow_pk="0" * 32)
        plan.context["pending_user"] = other if name != "plan-same" else user
        data["authentik/flows/plan"] = plan
    return data


cases = []
i = 0
for kwargs, req, ip, b, u, o, sess in product(KWARGS, REQUESTS, IPS, BRANDS, USERS, OVERRIDES, SESSIONS):
    i += 1
    # A deterministic spread over the product: every value of every axis.
    if i % 37 != 0 and not (req is None and i % 11 == 0):
        continue
    cases.append({"kwargs": kwargs, "request": req, "client_ip": ip, "brand": b, "user": u, "override": o,
                  "session": sess, "action": ["login", "logout", "foo"][i % 3]})

SQL = """SELECT action, app, context, host(client_ip), "user", brand,
         round(extract(epoch from expires - created)), expiring
         FROM authentik_events_event WHERE event_uuid = %s"""
out = []
with transaction.atomic():
    for case in cases:
        sid = transaction.savepoint()
        before = set(Task.objects.values_list("message_id", flat=True))
        request = None
        if case["request"] is not None:
            r = case["request"]
            path = r["path"] + (("?" + r["query"]) if r["query"] else "")
            request = RequestFactory().generic(r["method"], path, HTTP_USER_AGENT=r["ua"])
            if r["rid"] is not None:
                request.request_id = r["rid"]
            request.client_ip = case["client_ip"]
            if case["brand"] is not None:
                request.brand = {"default": default, "m8": brand, "fallback": DEFAULT_BRAND}[case["brand"]]
            if case["user"] is not None:
                request.user = user_obj(case["user"])
            if case["session"] is not None:
                data = pickle.loads(pickle.dumps(session_data(case["session"])))
                request.session = data
                case["session_pickle"] = pickle.dumps(session_data(case["session"])).hex()
        action = case["action"] if case["action"] != "foo" else "foo"
        event = Event.new(EventAction(action) if action != "foo" else action, app="authentik.events.signals",
                          **json.loads(json.dumps(case["kwargs"])))
        event.from_http(request, user=user_obj(case["override"]) if case["override"] else None)
        with connection.cursor() as cursor:
            cursor.execute(SQL, [event.event_uuid])
            row = list(cursor.fetchone())
        row[6] = int(row[6])
        # Django reads jsonb as text from a raw cursor.
        for col in (2, 4, 5):
            row[col] = json.loads(row[col]) if isinstance(row[col], str) else row[col]
        tasks = []
        for task in Task.objects.exclude(message_id__in=before):
            message = pickle.loads(bytes(task.message))
            tasks.append({"actor": task.actor_name, "queue": task.queue_name, "state": task.state,
                          "aggregated_status": task.aggregated_status, "retries": task.retries,
                          "args_match": list(message["args"]) == [event.event_uuid],
                          "logs": list(TaskLog.objects.filter(task=task).values_list("event", flat=True))})
        out.append({"case": case, "row": row, "tasks": tasks})
        transaction.savepoint_rollback(sid)
    transaction.set_rollback(True)

ids = {"user": user.pk, "other": other.pk, "brand": str(brand.pk), "default": str(default.pk),
       "fallback_pk": DEFAULT_BRAND.pk.hex}
print("EVENT_DECISIONS " + json.dumps({"ids": ids, "results": out}, default=str))
