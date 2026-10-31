#!/usr/bin/env python3
"""Create real sessions on a running stack and craft cookie variants.

Usage: sessions.py BASE_URL SECRET_KEY BOOTSTRAP_PASSWORD > cookies.json

Real sessions are made the way a browser makes them, through the flow
executor API: an anonymous in-flow session, logins (two concurrent ones
for the same user), an impersonating session, a session whose user is
deactivated afterwards, a logged-out session and one that is expired
afterwards (run.sh does the deactivation and expiry in SQL). Crafted
cookies are JWTs signed like authentik's, around a real session key,
exercising PyJWT's decode and claim checks.

Standard library only.
"""

import base64
import hashlib
import hmac
import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

BASE, SECRET_KEY, BOOTSTRAP_PASSWORD = sys.argv[1:4]
HOST = "authentik.test"


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def cookie(self, name):
        return next((c.value for c in self.jar if c.name == name), None)

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            BASE + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Host": HOST, "Accept": "application/json", "Content-Type": "application/json"},
            method=method,
        )
        if (csrf := self.cookie("authentik_csrf")) is not None:
            req.add_header("X-authentik-CSRF", csrf)
        try:
            with self.opener.open(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as err:
            return err.code, err.read()

    def login(self, username, password):
        flow = "/api/v3/flows/executor/default-authentication-flow/?query="
        self.call("GET", flow)
        self.call("POST", flow, {"component": "ak-stage-identification", "uid_field": username})
        status, body = self.call("POST", flow, {"component": "ak-stage-password", "password": password})
        assert status == 200 and body.get("component") == "xak-flow-redirect", (username, status, body)
        return self


def sid(cookie):
    payload = cookie.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["sid"]


real = {}
anonymous = Browser()
anonymous.call("GET", "/api/v3/flows/executor/default-authentication-flow/?query=")
real["anonymous-in-flow"] = anonymous.cookie("authentik_session")
real["user"] = Browser().login("m5-active", "m5-password").cookie("authentik_session")
admin = Browser().login("akadmin", BOOTSTRAP_PASSWORD)
real["admin-concurrent-1"] = admin.cookie("authentik_session")
real["admin-concurrent-2"] = Browser().login("akadmin", BOOTSTRAP_PASSWORD).cookie("authentik_session")
status, users = admin.call("GET", "/api/v3/core/users/?username=m5-active")
assert status == 200, users
status, body = admin.call("POST", f"/api/v3/core/users/{users['results'][0]['pk']}/impersonate/", {"reason": "m5 differential"})
assert status in (200, 201, 204), (status, body)
real["admin-impersonating"] = admin.cookie("authentik_session")
real["to-deactivate"] = Browser().login("m5-deactivate", "m5-password").cookie("authentik_session")
logout = Browser().login("m5-active", "m5-password")
real["logged-out"] = logout.cookie("authentik_session")
status, body = logout.call("GET", "/api/v3/flows/executor/default-invalidation-flow/?query=")
assert status == 200, (status, body)
real["to-expire"] = Browser().login("m5-active", "m5-password").cookie("authentik_session")
assert all(real.values()), real

# Crafted: signed like SessionMiddleware.encode_session, around a real key.
KEY = hashlib.sha512(SECRET_KEY.encode()).hexdigest().encode()
SID = sid(real["user"])


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def token(payload_json: str, header_json='{"alg":"HS256","typ":"JWT"}', key=KEY, sig_junk=""):
    signing_input = f"{b64(header_json.encode())}.{b64(payload_json.encode())}"
    signature = b64(hmac.new(key, signing_input.encode(), hashlib.sha256).digest())
    return f"{signing_input}.{sig_junk}{signature}"


def claims(**extra):
    body = {"sid": SID, "iss": "authentik", "sub": "anonymous", "authenticated": True, "acr": "goauthentik.io/core/default"}
    body.update(extra)
    return json.dumps(body)


S = json.dumps(SID)
crafted = {
    "valid": token(claims()),
    "wrong-key": token(claims(), key=b"nope"),
    "exp-past": token(claims(exp=1)),
    "exp-future": token(claims(exp=4102444800)),
    "exp-str-past": token(claims(exp="1")),
    "exp-str-future": token(claims(exp=" 4102444800 ")),
    "exp-null": token(claims(exp=None)),
    "exp-nan": token(claims()[:-1] + ', "exp": NaN}'),
    "exp-infinity": token(claims()[:-1] + ', "exp": Infinity}'),
    "exp-list": token(claims(exp=[1])),
    "exp-underscore": token(claims(exp="4_102_444_800")),
    "iat-future": token(claims(iat=4102444800)),
    "iat-past-float": token(claims(iat=1.9)),
    "iat-text": token(claims(iat="abc")),
    "nbf-future": token(claims(nbf=4102444800)),
    "aud-set": token(claims(aud="x")),
    "aud-empty": token(claims(aud="")),
    "aud-empty-list": token(claims(aud=[])),
    "sub-int": token(claims(sub=5)),
    "jti-int": token(claims(jti=5)),
    "jti-str": token(claims(jti="j")),
    "sid-int": token('{"sid": 12345678}'),
    "sid-true": token('{"sid": true}'),
    "sid-false": token('{"sid": false}'),
    "sid-short": token('{"sid": "short"}'),
    "sid-list": token('{"sid": [1,2,3,4,5,6,7,8]}'),
    "sid-missing": token('{"iss": "authentik"}'),
    "sid-lone-surrogate": token('{"sid": "\\ud800aaaaaaaa"}'),
    "sid-duplicate-last-wins": token('{"sid": "short", "sid": ' + S + "}"),
    "payload-list": token("[1]"),
    "payload-not-json": token("{oops"),
    "alg-none": token(claims(), header_json='{"alg":"none"}'),
    "alg-hs512": token(claims(), header_json='{"alg":"HS512"}'),
    "alg-missing": token(claims(), header_json='{"typ":"JWT"}'),
    "alg-list": token(claims(), header_json='{"alg":["HS256"]}'),
    "header-b64-false": token(claims(), header_json='{"alg":"HS256","b64":false}'),
    "header-kid-int": token(claims(), header_json='{"alg":"HS256","kid":5}'),
    "header-list": token(claims(), header_json="[]"),
    "header-deep-ok": token(claims(), header_json="[" * 500 + "]" * 500),
    "header-deep-recursion": token(claims(), header_json="[" * 3000 + "]" * 3000),
    "signature-junk": token(claims(), sig_junk="!!*"),
    "signature-latin1": token(claims(), sig_junk="é"),
    "two-segments": "a.b",
    "one-segment": "abc",
    "empty": "",
}
cookies = [{"name": f"real:{k}", "cookie": v, "sid": sid(v)} for k, v in real.items()]
cookies += [{"name": f"crafted:{k}", "cookie": v} for k, v in crafted.items()]
cookies.append({"name": "absent", "cookie": None})
json.dump(cookies, sys.stdout, ensure_ascii=False)
