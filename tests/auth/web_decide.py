# Run with `python -m manage shell` in the reference container (run.sh).
"""Django's answers for the request/response pieces of M5, as JSON: each case
carries its inputs and what 2026.2.7 decides, so ak-auth's test replays the
inputs and compares.

- csrf: CsrfViewMiddleware (and DRF's CSRFCheck on a DRF Request with only
  the JSON parser) over methods, hosts, TLS, Origin/Referer, cookies, header
  and form tokens.
- tokens: _mask_cipher_secret with a known mask, _unmask_cipher_token and
  _get_secret on assorted cookies.
- cookies: set_cookie/delete_cookie rendered by Morsel at a frozen time,
  patch_vary_headers, http_date.
- session_cookie: SessionMiddleware.encode_session and process_response.
- csrf_cookie: CsrfViewMiddleware.process_response.
- is_secure: request.is_secure() and SessionMiddleware.is_secure().
- redirects: redirect_to_login(request.get_full_path()) for raw targets.
- bindings: BoundSessionMiddleware.recheck_session with the image's
  GeoLite2 databases.
"""

import json
import random
import time
import types
from urllib.parse import unquote_to_bytes

import django.http.response
from django.conf import settings
from django.contrib.auth.views import redirect_to_login
from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse
from django.middleware import csrf as django_csrf
from django.test import RequestFactory, override_settings
from django.utils.cache import patch_vary_headers
from django.utils.http import http_date
from drf_orjson_renderer.parsers import ORJSONParser
from rest_framework.authentication import CSRFCheck
from rest_framework.exceptions import APIException
from rest_framework.request import Request

import authentik.root.middleware as ak_middleware
from authentik.root.middleware import CsrfViewMiddleware, SessionMiddleware
from authentik.stages.user_login.middleware import (
    SESSION_KEY_BINDING_GEO,
    SESSION_KEY_BINDING_NET,
    BoundSessionMiddleware,
    SessionBindingBroken,
)

NOW = 1793440000.75
rng = random.Random(20261031)
chars = django_csrf.CSRF_ALLOWED_CHARS


def rand(n):
    return "".join(rng.choice(chars) for _ in range(n))


class FrozenTime:
    @staticmethod
    def time():
        return NOW


django.http.response.time = FrozenTime
ak_middleware.time = FrozenTime.time
out = {"now": NOW}

# --- csrf -------------------------------------------------------------------
secret = rand(32)
masked = django_csrf._mask_cipher_secret(secret)
other = rand(32)
TOKENS = {
    "none": None, "secret": secret, "masked": masked, "masked2": django_csrf._mask_cipher_secret(secret),
    "other": other, "short": "abc", "bad-chars": "!" * 32, "non-ascii": "é" * 32, "len-33": secret + "a",
    "masked-other": django_csrf._mask_cipher_secret(other), "empty": "",
}
HOST = "authentik.test"
csrf_cases = []
for method in ["GET", "HEAD", "OPTIONS", "TRACE", "POST", "PUT", "PATCH", "DELETE", "post"]:
    csrf_cases.append({"method": method, "cookie": "secret", "header": None})
for cookie in TOKENS:
    for header in ["none", "secret", "masked", "other", "short", "bad-chars", "masked-other", "empty", "non-ascii"]:
        csrf_cases.append({"method": "POST", "cookie": cookie, "header": header})
for cookie in ["masked", "len-33"]:
    csrf_cases.append({"method": "PUT", "cookie": cookie, "header": "masked2"})
for origin in [None, "http://authentik.test", "https://authentik.test", "http://evil.test", "", "null",
               "http://authentik.test:80", "http://AUTHENTIK.test"]:
    for secure in [False, True]:
        csrf_cases.append({"method": "POST", "cookie": "secret", "header": "masked", "origin": origin,
                           "secure": secure, "referer": "https://authentik.test/x"})
for referer in [None, "", "https://authentik.test/", "https://authentik.test:443/", "http://authentik.test/",
                "https://evil.test/", "https://sub.authentik.test/", "//authentik.test/", "https:///x",
                "https://[::1/", "https://[1.2.3.4]/", "https://user@authentik.test/p?q#f", "ftp://authentik.test/",
                " https://authentik.test/", "https://authentik.test\t/", "HTTPS://AUTHENTIK.TEST/",
                "https://[v1.x]/", "https://exämple.test/", "https://a℀b/"]:
    csrf_cases.append({"method": "POST", "cookie": "secret", "header": "masked", "secure": True, "referer": referer})
for host in ["authentik.test:9000", "bad host", "[::1]:9000"]:
    csrf_cases.append({"method": "POST", "cookie": "secret", "header": "masked", "secure": True,
                       "referer": f"https://{host}/", "host": host})
    csrf_cases.append({"method": "POST", "cookie": "secret", "header": "masked", "origin": f"http://{host}",
                       "host": host})
for xfp in ["https", "http", "https, http", " https ", "HTTPS", "", " https"]:
    csrf_cases.append({"method": "POST", "cookie": "secret", "header": "masked", "xfp": xfp,
                       "referer": "https://evil.test/"})
for body in [("form", "csrfmiddlewaretoken=" + masked), ("form", "csrfmiddlewaretoken=nope"),
             ("form", "a=1&csrfmiddlewaretoken=x&csrfmiddlewaretoken=" + secret), ("form", "csrfmiddlewaretoken="),
             ("json", '{"csrfmiddlewaretoken": "x"}'), ("json-bad", "{"), ("form", ""), ("text", "hello")]:
    for header in ["none", "masked"]:
        csrf_cases.append({"method": "POST", "cookie": "secret", "header": header, "body": body})
        csrf_cases.append({"method": "PUT", "cookie": "secret", "header": header, "body": body})

CONTENT_TYPES = {"form": "application/x-www-form-urlencoded", "json": "application/json",
                 "json-bad": "application/json", "text": "text/plain"}


def build_request(case):
    meta = {"HTTP_HOST": case.get("host", HOST)}
    if case.get("origin") is not None:
        meta["HTTP_ORIGIN"] = case["origin"]
    if case.get("referer") is not None:
        meta["HTTP_REFERER"] = case["referer"]
    if case.get("xfp") is not None:
        meta["HTTP_X_FORWARDED_PROTO"] = case["xfp"]
    if TOKENS.get(case.get("header") or "none") is not None:
        meta["HTTP_X_AUTHENTIK_CSRF"] = TOKENS[case["header"]]
    kind, body = case.get("body") or ("json", "")
    request = RequestFactory().generic(case["method"], "/api/v3/x/", body.encode(),
                                       content_type=CONTENT_TYPES[kind], secure=case.get("secure", False), **meta)
    if TOKENS.get(case["cookie"]) is not None:
        request.COOKIES[settings.CSRF_COOKIE_NAME] = TOKENS[case["cookie"]]
    return request


for case in csrf_cases:
    # Django: CsrfViewMiddleware on a plain request (form bodies parsed).
    request = build_request(case)
    check = CSRFCheck(lambda r: None)
    check.process_request(request)
    meta_cookie = request.META.get("CSRF_COOKIE")
    case["needs_update"] = bool(request.META.get("CSRF_COOKIE_NEEDS_UPDATE"))
    case["meta_cookie"] = meta_cookie if not case["needs_update"] else None
    case["is_secure"] = request.is_secure()
    case["post_token"] = request.POST.get("csrfmiddlewaretoken", "") if request.method == "POST" else ""
    case["request_method"] = request.method
    case["django"] = check.process_view(request, None, (), {})
    # What DRF's request.POST yields for the same request, separately.
    if request.method == "POST":
        try:
            case["drf_post"] = Request(build_request(case), parsers=[ORJSONParser()]).POST.get(
                "csrfmiddlewaretoken", "")
        except APIException as exc:
            case["drf_post"] = f"body_error:{type(exc).__name__}"
    else:
        case["drf_post"] = ""
    # DRF: the same checks on a DRF Request (JSON parser only).
    drf_request = Request(build_request(case), parsers=[ORJSONParser()])
    try:
        check = CSRFCheck(lambda r: None)
        check.process_request(drf_request)
        case["drf"] = check.process_view(drf_request, None, (), {})
    except APIException as exc:
        case["drf"] = f"body_error:{type(exc).__name__}"
    case["header_value"] = TOKENS.get(case.get("header") or "none")
    case["cookie_value"] = TOKENS.get(case["cookie"])
out["csrf"] = csrf_cases

# --- tokens -----------------------------------------------------------------
tokens = []
for _ in range(50):
    s, m = rand(32), rand(32)
    django_csrf._get_new_csrf_string = lambda m=m: m
    token = django_csrf._mask_cipher_secret(s)
    tokens.append({"secret": s, "mask": m, "token": token, "unmasked": django_csrf._unmask_cipher_token(token)})
out["tokens"] = tokens
secrets = []
mw = CsrfViewMiddleware(lambda r: None)
for value in list(TOKENS.values()) + ["a" * 64, "é" * 64, "a" * 31, "A1" * 16]:
    request = RequestFactory().get("/")
    if value is not None:
        request.COOKIES[settings.CSRF_COOKIE_NAME] = value
    try:
        secrets.append({"cookie": value, "secret": mw._get_secret(request)})
    except django_csrf.InvalidTokenFormat as exc:
        secrets.append({"cookie": value, "error": exc.reason})
out["secrets"] = secrets

# --- cookies ----------------------------------------------------------------
cookie_cases = []
for value in ["v", "", "a b", 'x"y', "back\\slash", "é", "€", "a;b", "a,b", "tab\there", "del\x7f",
              "jwt.eyJ-_x", "=", "(paren)"]:
    cookie_cases.append({"name": "c", "value": value})
for kw in [{"max_age": 3600}, {"max_age": 3600.9}, {"max_age": 0}, {"max_age": -5}, {"expires": "Sun, 01 Jan 2040 00:00:00 GMT"},
           {"max_age": 60, "expires": "x"}, {"path": "/sub/"}, {"path": ""}, {"domain": ".authentik.test"},
           {"domain": ""}, {"secure": True}, {"httponly": True}, {"samesite": "Lax"}, {"samesite": "None"},
           {"samesite": "Strict"}, {"path": "/p\n"}, {"max_age": 86400, "path": "/", "domain": "d", "secure": True,
                                                    "httponly": True, "samesite": "None"}]:
    cookie_cases.append({"name": "c", "value": "v", **kw})
for case in cookie_cases:
    response = HttpResponse()
    kwargs = {k: v for k, v in case.items() if k not in ("name", "value")}
    try:
        response.set_cookie(case["name"], case["value"], **kwargs)
        case["output"] = response.cookies[case["name"]].OutputString()
    except Exception as exc:  # noqa: BLE001
        case["output"] = f"error:{type(exc).__name__}"
delete_cases = []
for name, path, domain, samesite in [("authentik_session", "/", None, "Lax"), ("authentik_session", "/", None, "None"),
                                     ("__Secure-x", "/a/", "d.test", None), ("c", "/", None, "none")]:
    response = HttpResponse()
    response.delete_cookie(name, path=path, domain=domain, samesite=samesite)
    delete_cases.append({"name": name, "path": path, "domain": domain, "samesite": samesite,
                         "output": response.cookies[name].OutputString()})
vary_cases = []
for existing in [None, "Accept-Encoding", "Cookie", "cookie", "Accept,  Cookie", "*", "Accept , Origin ", " Accept",
                 "a,,b", "Accept , x"]:
    response = HttpResponse()
    if existing is not None:
        response.headers["Vary"] = existing
    patch_vary_headers(response, ("Cookie",))
    vary_cases.append({"existing": existing, "vary": response.headers["Vary"]})
out["cookies"] = {"set": cookie_cases, "delete": delete_cases, "vary": vary_cases,
                  "http_date": [{"t": t, "date": http_date(t)} for t in [0, 0.999, NOW, NOW + 31449600, 4102444800.5]]}

# --- session cookie ---------------------------------------------------------
users = {"anonymous": types.SimpleNamespace(is_authenticated=False, uid=None),
         "user": types.SimpleNamespace(is_authenticated=True, uid="a" * 64),
         "odd": types.SimpleNamespace(is_authenticated=True, uid="é\"\\\n ")}
encodings = []
for key in ["k" * 32, "x", "été"]:
    for user in users:
        encodings.append({"key": key, "user": user, "uid": users[user].uid,
                          "jwt": SessionMiddleware.encode_session(key, users[user])})


class FakeSession:
    def __init__(self, c):
        self.accessed, self.modified, self.session_key = c["accessed"], c["modified"], c["key"]
        self._empty, self._expiry, self.saved = c["empty"], c["expiry"], False

    def is_empty(self):
        return self._empty

    def get_expire_at_browser_close(self):
        return self._expiry is None

    def get_expiry_age(self):
        return self._expiry

    def save(self):
        self.saved = True


responses = []
for had_cookie in [False, True]:
    for accessed in [False, True]:
        for modified in [False, True]:
            for empty in [False, True]:
                for status in [200, 500]:
                    for secure in [False, True]:
                        for expiry in [None, 3600, 1209599.5]:
                            for user in ["anonymous", "user"]:
                                responses.append({"had_cookie": had_cookie, "accessed": accessed,
                                                  "modified": modified, "empty": empty, "status": status,
                                                  "secure": secure, "expiry": expiry, "user": user,
                                                  "key": None if empty else "s" * 32})
for case in responses:
    request = RequestFactory().get("/", secure=case["secure"], HTTP_HOST=HOST)
    if case["had_cookie"]:
        request.COOKIES[settings.SESSION_COOKIE_NAME] = "old"
    request.session = FakeSession(case)
    request.user = users[case["user"]]
    response = HttpResponse(status=case["status"])
    SessionMiddleware(lambda r: response).process_response(request, response)
    case["uid"] = users[case["user"]].uid
    case["cookies"] = [c.OutputString() for c in response.cookies.values()]
    case["vary"] = response.headers.get("Vary")
    case["saved"] = request.session.saved
csrf_cookie = []
for needs_update in [False, True]:
    for secure in [False, True]:
        request = RequestFactory().get("/", secure=secure, HTTP_HOST=HOST)
        request.META["CSRF_COOKIE"] = secret
        request.META["CSRF_COOKIE_NEEDS_UPDATE"] = needs_update
        response = HttpResponse()
        CsrfViewMiddleware(lambda r: response).process_response(request, response)
        csrf_cookie.append({"needs_update": needs_update, "secure": secure, "cookie": secret,
                            "cookies": [c.OutputString() for c in response.cookies.values()],
                            "vary": response.headers.get("Vary")})
out["session_cookie"] = {"secret_key": settings.SECRET_KEY, "encode": encodings, "responses": responses,
                         "csrf": csrf_cookie, "web_path": settings.SESSION_COOKIE_PATH}

# --- is_secure --------------------------------------------------------------
secure_cases = []
for debug in [False, True]:
    for host in ["authentik.test", "localhost", "localhost:9000", "LOCALHOST"]:
        for ua in ["", "goauthentik.io/outpost/2026.2.7", "Mozilla Safari/605", "Chrome Safari", "SAFARI"]:
            for scheme in [False, True]:
                request = RequestFactory().get("/", secure=scheme, HTTP_HOST=host, HTTP_USER_AGENT=ua)
                with override_settings(DEBUG=debug):
                    secure_cases.append({"debug": debug, "host": host, "ua": ua, "request_secure": request.is_secure(),
                                         "secure": SessionMiddleware.is_secure(request)})
out["is_secure"] = secure_cases

# --- redirects --------------------------------------------------------------
redirects = []
for target in ["/", "/api/v3/core/users/?page=2", "/if/admin/#/x", "/a%20b/", "/%C3%A9t%C3%A9/", "/%FF%FE/",
               "/caf%C3", "/q?next=/a&b=%2F", "/q?é=1", "/;x=1", "/a//b", "/%2F/", "/sp ace?x y", "/'\"<>/",
               "/~user/(x)*!", "/?", "/??", "/p?%zz"]:
    path, _, query = target.partition("?")
    environ = RequestFactory()._base_environ(
        PATH_INFO=unquote_to_bytes(path).decode("latin-1"), QUERY_STRING=query, REQUEST_METHOD="GET")
    request = WSGIRequest(environ)
    redirects.append({"path_info_raw": path, "query": query, "full_path": request.get_full_path(),
                      "location": redirect_to_login(request.get_full_path())["Location"]})
out["redirects"] = redirects

# --- bindings ---------------------------------------------------------------
NETS = [None, "no_binding", "bind_asn", "bind_asn_network", "bind_asn_network_ip", "other"]
GEOS = [None, "no_binding", "bind_continent", "bind_continent_country", "bind_continent_country_city"]
PAIRS = [("8.8.8.8", "8.8.8.8"), ("8.8.8.8", "8.8.8.9"), ("8.8.8.8", "8.8.4.4"), ("8.8.8.8", "1.1.1.1"),
         ("8.8.8.8", "10.0.0.1"), ("10.0.0.1", "10.0.0.2"), ("81.2.69.142", "81.2.69.160"),
         ("81.2.69.142", "8.8.8.8"), ("2001:4860:4860::8888", "8.8.8.8"), ("2001:4860:4860::8888", "2001:4860:4860::8844"),
         ("::ffff:8.8.8.8", "8.8.8.8"), ("8.8.8.8", "255.255.255.255"), ("36.86.63.180", "36.86.63.181"),
         ("36.86.63.180", "103.10.20.30"), ("1.1.1.1", "1.0.0.1"), ("8.8.8.8", "not-an-ip")]
for _ in range(60):
    a = ".".join(str(rng.randrange(1, 224)) for _ in range(4))
    b = ".".join(a.split(".")[:3] + [str(rng.randrange(0, 256))]) if rng.random() < 0.5 else \
        ".".join(str(rng.randrange(1, 224)) for _ in range(4))
    PAIRS.append((a, b))
bindings = []
for last_ip, new_ip in PAIRS:
    for net in NETS:
        for geo in GEOS:
            if net not in (None, "no_binding") and geo not in (None, "no_binding") and rng.random() < 0.7:
                continue
            session = {"last_ip": last_ip}
            if net is not None:
                session[SESSION_KEY_BINDING_NET] = net
            if geo is not None:
                session[SESSION_KEY_BINDING_GEO] = geo
            request = types.SimpleNamespace(session=session, client_ip=new_ip, META={})
            try:
                BoundSessionMiddleware(lambda r: None).recheck_session(request)
                if session["last_ip"] != last_ip:
                    result = "passed:set_last_ip"
                elif last_ip == new_ip:
                    result = "unchanged"
                else:
                    result = "passed"
            except SessionBindingBroken as exc:
                result = f"broken:{exc.reason}"
            except Exception as exc:  # noqa: BLE001
                result = f"error:{type(exc).__name__}"
            bindings.append({"last_ip": last_ip, "new_ip": new_ip, "net": net, "geo": geo, "result": result})
out["bindings"] = bindings

# --- client IP --------------------------------------------------------------
from django.db import transaction  # noqa: E402

from authentik.root.middleware import ClientIPMiddleware  # noqa: E402

client_ips = []
addresses = [None, "", "203.0.113.9", " 203.0.113.9 ", "203.0.113.9, 10.0.0.1", "10.0.0.1,203.0.113.9", "bad",
             "2001:DB8::0:1", "2001:db8:0:0:1:0:0:1", "::ffff:1.2.3.4", "::1.2.3.4", "fe80::1%eth0", "fe80::1%",
             "1.2.3.04", "1.2.3.4/32", "\u00a0203.0.113.9", "[::1]", "::", "0:0:0:0:0:0:0:0", "1:0:0:2:0:0:0:3",
             "1.2.3.4%x", "203.0.113.9:80"]
with transaction.atomic():
    for xff in addresses[:6] + ["2001:DB8::0:1", "bad, 1.2.3.4", "fe80::1%eth0", "\u00a0203.0.113.9"]:
        for remote in [None, "198.51.100.1"]:
            client_ips.append({"xff": xff, "remote": remote, "remote_ip": None, "token": None})
    for remote in addresses:
        client_ips.append({"xff": None, "remote": remote, "remote_ip": None, "token": None})
    for token in [None, "m5-service", "m5-service-expired", "m5-service-recovery", "m5-sa", "m5-api-active", "nope"]:
        for remote_ip in [None, "192.0.2.7", "2001:db8::7", "bad", ""]:
            client_ips.append({"xff": "203.0.113.9", "remote": "198.51.100.1", "remote_ip": remote_ip, "token": token})
    for case in client_ips:
        request = RequestFactory().get("/")
        request.META.pop("REMOTE_ADDR", None)
        for key, header in [("xff", "HTTP_X_FORWARDED_FOR"), ("remote", "REMOTE_ADDR"),
                            ("remote_ip", "HTTP_X_AUTHENTIK_REMOTE_IP"), ("token", "HTTP_X_AUTHENTIK_OUTPOST_TOKEN")]:
            if case[key] is not None:
                request.META[header] = case[key]
        case["ip"] = ClientIPMiddleware(lambda r: None)._get_client_ip(request)
        outpost_user = ClientIPMiddleware.get_outpost_user(request)
        case["outpost_user"] = outpost_user.pk if outpost_user else None
    transaction.set_rollback(True)
out["client_ip"] = client_ips

print("WEB_DECISIONS " + json.dumps(out, ensure_ascii=False))
