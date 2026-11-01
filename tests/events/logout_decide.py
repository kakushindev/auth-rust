# Appended after `CASES = …` by run.sh; run with `python -m manage shell`.
"""What Django writes when its session middlewares log a session out.

For each case (logout_populate.py), the request runs through
ClientIPMiddleware, BoundSessionMiddleware.process_request and
AuthenticationMiddleware.process_request in a savepoint rolled back
afterwards. Recorded: the response, the events created (as SQL reads them),
the tasks enqueued (actor and whether the argument is the event or the
session key), and whether the session, its AuthenticatedSession and the
user still exist.
"""

import json
import pickle

from django.conf import settings
from django.db import connection, transaction
from django.test import RequestFactory

from authentik.core.middleware import AuthenticationMiddleware
from authentik.root.middleware import ClientIPMiddleware
from authentik.stages.user_login.middleware import BoundSessionMiddleware
from authentik.tasks.models import Task

EVENTS = """SELECT action, app, context, host(client_ip), "user", brand,
            round(extract(epoch from expires - created)), expiring, event_uuid
            FROM authentik_events_event WHERE created >= %s ORDER BY created, event_uuid"""
out = []
with transaction.atomic():
    for case in CASES:  # noqa: F821
        sid = transaction.savepoint()
        with connection.cursor() as cursor:
            cursor.execute("SELECT now()")
            start = cursor.fetchone()[0]
        before = set(Task.objects.values_list("message_id", flat=True))
        path = case["path"] + (("?" + case["query"]) if case["query"] else "")
        request = RequestFactory().get(path, REMOTE_ADDR=case["client_ip"], HTTP_USER_AGENT=case["user_agent"],
                                       HTTP_HOST="authentik.test")
        request.COOKIES[settings.SESSION_COOKIE_NAME] = case["cookie"]
        user_pk = None
        try:
            ClientIPMiddleware(lambda r: None)(request)
            response = BoundSessionMiddleware(lambda r: None).process_request(request)
            if response is None:
                response = AuthenticationMiddleware(lambda r: None).process_request(request)
            result = "none" if response is None else f"{response.status_code}:{response.get('Location', '')}"
        except Exception as exc:  # noqa: BLE001
            result = f"error:{type(exc).__name__}"
        with connection.cursor() as cursor:
            cursor.execute(EVENTS, [start])
            events = []
            for row in cursor.fetchall():
                row = list(row)
                for col in (2, 4, 5):
                    row[col] = json.loads(row[col]) if isinstance(row[col], str) else row[col]
                row[6] = int(row[6])
                events.append(row)
            cursor.execute("SELECT EXISTS (SELECT 1 FROM authentik_core_session WHERE session_key = %s), "
                           "EXISTS (SELECT 1 FROM authentik_core_authenticatedsession WHERE session_id = %s)",
                           [case["session_key"], case["session_key"]])
            session_exists, authenticated_exists = cursor.fetchone()
            cursor.execute("SELECT count(*) FROM authentik_core_user WHERE username = 'm8-doomed'")
            doomed = cursor.fetchone()[0]
        event_ids = {str(e[8]) for e in events}
        tasks = []
        for task in Task.objects.exclude(message_id__in=before).order_by("actor_name"):
            arg = pickle.loads(bytes(task.message))["args"][0]
            kind = "event" if str(arg) in event_ids else ("session_key" if arg == case["session_key"] else repr(arg))
            tasks.append([task.actor_name, kind, task.state])
        out.append({"case": case, "result": result, "events": [e[:8] for e in events], "tasks": sorted(tasks),
                    "session": session_exists, "authenticated_session": authenticated_exists,
                    "doomed_user": doomed})
        transaction.savepoint_rollback(sid)
    transaction.set_rollback(True)
print("LOGOUT_DECISIONS " + json.dumps(out, default=str))
