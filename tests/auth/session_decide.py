# Appended after `COOKIES = …` by run.sh; run with `python -m manage shell`.
"""Django's request identity for each session cookie, as JSON: the real
middleware order (ClientIPMiddleware, BoundSessionMiddleware,
AuthenticationMiddleware, then ImpersonateMiddleware's check), inside a
rolled-back transaction (logout flushes sessions)."""

import json

from django.conf import settings
from django.db import transaction
from django.test import RequestFactory

from authentik.core.middleware import SESSION_KEY_IMPERSONATE_USER, AuthenticationMiddleware
from authentik.root.middleware import ClientIPMiddleware
from authentik.stages.user_login.middleware import BoundSessionMiddleware

CLIENT_IP = "203.0.113.9"
out = []
with transaction.atomic():
    for case in COOKIES:  # noqa: F821
        request = RequestFactory().get("/", HTTP_HOST="authentik.test", REMOTE_ADDR=CLIENT_IP)
        if case["cookie"] is not None:
            request.COOKIES[settings.SESSION_COOKIE_NAME] = case["cookie"]
        try:
            ClientIPMiddleware(lambda r: None)(request)
            if BoundSessionMiddleware(lambda r: None).process_request(request) is not None:
                result = "binding_check"
            elif (response := AuthenticationMiddleware(lambda r: None).process_request(request)) is not None:
                result = f"status:{response.status_code}"
            elif SESSION_KEY_IMPERSONATE_USER in request.session:
                real = request.user.pk if request.user.is_authenticated else None
                result = f"impersonating:{real}:{request.session[SESSION_KEY_IMPERSONATE_USER].pk}"
            elif request.user.is_authenticated:
                result = f"user:{request.user.pk}"
            else:
                result = "anonymous"
        except Exception as exc:  # noqa: BLE001 - Django answers 500
            result = f"error:{type(exc).__name__}"
        out.append({"name": case["name"], "result": result})
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
print("SESSION_DECISIONS " + json.dumps({"decisions": out, "pickles": pickles}))
