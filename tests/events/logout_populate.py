# Run with `python -m manage shell` after event_populate.py (run.sh).
"""Sessions the session middlewares log out, one per scenario, as JSON.

Each scenario gets its own session (saved through SessionStore, with an
AuthenticatedSession unless anonymous) and a request (path, query, user
agent, client IP). Inactive users are logged out by AuthenticationMiddleware;
bound sessions requested from another IP by BoundSessionMiddleware.
"""

import json
from datetime import timedelta

from django.utils.timezone import now

from authentik.core.models import AuthenticatedSession, User
from authentik.core.sessions import SessionStore
from authentik.flows.planner import FlowPlan
from authentik.providers.oauth2.models import AccessToken, OAuth2Provider
from authentik.root.middleware import SessionMiddleware
from authentik.flows.models import Flow

active = User.objects.get(username="m8-user")
other = User.objects.get(username="m8-other")
inactive = User.objects.create(username="m8-inactive", email="inactive@example.test", is_active=False)
doomed = User.objects.create(username="m8-doomed", is_active=False,
                             attributes={"goauthentik.io/user/delete-on-logout": True})
NET, GEO = "authentik/stages/user_login/binding/net", "authentik/stages/user_login/binding/geo"

SCENARIOS = [
    # name, user, last_ip, client_ip, extra session data, path, query
    ("inactive", inactive, "203.0.113.9", "203.0.113.9", {}, "/api/v3/core/users/", "a=1&token=x"),
    ("broken-asn", active, "8.8.8.8", "1.1.1.1", {NET: "bind_asn"}, "/api/v3/rbac/roles/", ""),
    ("broken-continent", active, "81.2.69.142", "8.8.8.8", {GEO: "bind_continent"}, "/", "query=x%3D1"),
    ("broken-missing", active, "8.8.8.8", "10.0.0.1", {NET: "bind_asn"}, "/api/v3/x/", ""),
    ("broken-network", active, "8.8.8.8", "8.8.4.4", {NET: "bind_asn_network"}, "/api/v3/x/", ""),
    ("broken-ip", active, "8.8.8.8", "8.8.8.9", {NET: "bind_asn_network_ip"}, "/api/v3/x/", ""),
    ("broken-anonymous", None, "8.8.8.8", "1.1.1.1", {NET: "bind_asn"}, "/api/v3/x/", ""),
    ("broken-inactive", inactive, "8.8.8.8", "1.1.1.1", {NET: "bind_asn"}, "/api/v3/x/", "b=2"),
    ("broken-impersonating", active, "8.8.8.8", "1.1.1.1",
     {NET: "bind_asn", "authentik/impersonate/original_user": other, "authentik/impersonate/user": active},
     "/api/v3/x/", ""),
    ("inactive-plan", inactive, "203.0.113.9", "203.0.113.9", {"plan": other}, "/if/flow/x/", ""),
    ("declined-delete-on-logout", doomed, "203.0.113.9", "203.0.113.9", {}, "/api/v3/x/", ""),
    ("declined-oauth2-token", inactive, "203.0.113.9", "203.0.113.9", {"token": True}, "/api/v3/x/", ""),
]
provider = OAuth2Provider.objects.create(
    name="m8-oauth2", authorization_flow=Flow.objects.get(slug="default-provider-authorization-explicit-consent"),
    invalidation_flow=Flow.objects.get(slug="default-provider-invalidation-flow"))
cases = []
for name, user, last_ip, client_ip, extra, path, query in SCENARIOS:
    store = SessionStore(last_ip=last_ip, last_user_agent="m8")
    store["last_ip"] = last_ip
    token = extra.pop("token", False)
    pending = extra.pop("plan", None)
    for key, value in extra.items():
        store[key] = value
    if pending is not None:
        plan = FlowPlan(flow_pk="0" * 32)
        plan.context["pending_user"] = pending
        store["authentik/flows/plan"] = plan
    store.create()
    if user is not None:
        session = AuthenticatedSession.objects.create(session_id=store.session_key, user=user)
        if token:
            AccessToken.objects.create(provider=provider, user=user, auth_time=now(), token="m8-" + name,
                                       _id_token="{}", _scope="openid", expires=now() + timedelta(hours=1),
                                       session=session)
    cookie = SessionMiddleware.encode_session(store.session_key, user or __import__(
        "django.contrib.auth.models", fromlist=["AnonymousUser"]).AnonymousUser())
    cases.append({"name": name, "session_key": store.session_key, "cookie": cookie, "client_ip": client_ip,
                  "path": path, "query": query, "user_agent": "Mozilla/5.0 m8"})
print("LOGOUT_CASES " + json.dumps(cases))
