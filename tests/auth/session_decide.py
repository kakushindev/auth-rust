# Appended after `COOKIES = …` by run.sh; run with `python -m manage shell`.
"""Django's request identity for each session cookie, and the response's
session cookie, as JSON.

The real middleware order (ClientIPMiddleware, BoundSessionMiddleware,
AuthenticationMiddleware, then ImpersonateMiddleware's check) runs for
each cookie from its client IP, in a savepoint rolled back afterwards
(logout flushes sessions). The response (the binding redirect, the 400, or
a 200) then goes through SessionMiddleware.process_response. Time is
frozen at NOW for both, so the Rust side can replay it."""

import json
import time
from datetime import UTC, datetime

import django.http.response
import django.utils.timezone
from django.conf import settings
from django.db import transaction
from django.http import HttpResponse
from django.test import RequestFactory

import authentik.root.middleware as ak_middleware
from authentik.core.middleware import SESSION_KEY_IMPERSONATE_USER, AuthenticationMiddleware
from authentik.root.middleware import ClientIPMiddleware
from authentik.stages.user_login.middleware import BoundSessionMiddleware

NOW = float(int(time.time()))


class FrozenTime:
    @staticmethod
    def time():
        return NOW


django.http.response.time = FrozenTime
ak_middleware.time = FrozenTime.time
django.utils.timezone.now = lambda: datetime.fromtimestamp(NOW, UTC)

CLIENT_IP = "203.0.113.9"
out = []
with transaction.atomic():
    for case in COOKIES:  # noqa: F821
        sid = transaction.savepoint()
        request = RequestFactory().get(
            "/", HTTP_HOST="authentik.test", REMOTE_ADDR=case.get("client_ip", CLIENT_IP)
        )
        if case["cookie"] is not None:
            request.COOKIES[settings.SESSION_COOKIE_NAME] = case["cookie"]
        middleware = BoundSessionMiddleware(lambda r: None)
        saved = []
        try:
            ClientIPMiddleware(lambda r: None)(request)
            if (response := middleware.process_request(request)) is not None:
                result = f"redirect:{response['Location']}"
            elif (response := AuthenticationMiddleware(lambda r: None).process_request(request)) is not None:
                result = f"status:{response.status_code}"
            else:
                response = HttpResponse()
                if SESSION_KEY_IMPERSONATE_USER in request.session:
                    real = request.user.pk if request.user.is_authenticated else None
                    request.user = request.session[SESSION_KEY_IMPERSONATE_USER]
                    result = f"impersonating:{real}:{request.user.pk}"
                elif request.user.is_authenticated:
                    result = f"user:{request.user.pk}"
                else:
                    result = "anonymous"
            save = request.session.save
            request.session.save = lambda *a, **k: (saved.append(True), save(*a, **k))
            middleware.process_response(request, response)
            cookies = [c.OutputString() for c in response.cookies.values()]
            vary = response.headers.get("Vary")
        except Exception as exc:  # noqa: BLE001 - Django answers 500
            result, cookies, vary = f"error:{type(exc).__name__}", [], None
        out.append({"name": case["name"], "result": result, "cookies": cookies, "vary": vary,
                    "saved": bool(saved)})
        transaction.savepoint_rollback(sid)
    transaction.set_rollback(True)


def describe(v):
    """Type and value or length, comparing exact builtin types (a StrEnum
    member is an object, not a str), as ak-pickle describes a pickle."""
    from django.db.models import Model

    if isinstance(v, Model):
        return {"type": f"model:{v._meta.app_label}.{type(v).__name__}"}
    t = type(v)
    out = {"type": t.__qualname__ if t.__module__ == "builtins" else f"{t.__module__}.{t.__qualname__}"}
    if v is None or t in (bool, int, str):
        out["value"] = str(v)
    elif t in (list, tuple, dict, set, frozenset, bytes, bytearray):
        out["len"] = len(v)
    return out


from authentik.core.models import Session  # noqa: E402
from authentik.core.sessions import SessionStore  # noqa: E402

pickles = []
for session in Session.objects.all().order_by("session_key"):
    data = SessionStore().decode(bytes(session.session_data))
    pickles.append({"session_key": session.session_key, "data": {k: describe(v) for k, v in data.items()}})
print("SESSION_DECISIONS " + json.dumps({"now": NOW, "decisions": out, "pickles": pickles}))
