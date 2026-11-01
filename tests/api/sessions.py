#!/usr/bin/env python3
"""Session cookies for the read-API differential (M8).

Usage: sessions.py BASE_URL > sessions.json

Runs against the reference after populate.py and before the snapshot is
dumped, so every stack restores the same session rows and the cookies
(JWTs signed with the shared SECRET_KEY) are valid everywhere. Logins go
through the flow executor the way a browser makes them. The output maps a
case name to the cookie value; run.sh then deactivates m8-sess-inactive
and expires one session in SQL.

Standard library only.
"""

import http.cookiejar
import json
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1]
HOST = "authentik.test"
PASSWORD = "m8-test-password"  # set by populate.py; a test value


class Browser:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def cookie(self, name="authentik_session"):
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

    def login(self, username):
        flow = "/api/v3/flows/executor/default-authentication-flow/?query="
        self.call("GET", flow)
        self.call("POST", flow, {"component": "ak-stage-identification", "uid_field": username})
        status, body = self.call("POST", flow, {"component": "ak-stage-password", "password": PASSWORD})
        assert status == 200 and body.get("component") == "xak-flow-redirect", (username, status, body)
        return self


cookies = {}
anonymous = Browser()
anonymous.call("GET", "/api/v3/flows/executor/default-authentication-flow/?query=")
cookies["session-anonymous"] = anonymous.cookie()
cookies["session-plain"] = Browser().login("m8-sess-plain").cookie()
cookies["session-super"] = Browser().login("m8-sess-super").cookie()
cookies["session-inactive"] = Browser().login("m8-sess-inactive").cookie()
cookies["session-expired"] = Browser().login("m8-sess-plain").cookie()
logout = Browser().login("m8-sess-plain")
cookies["session-logged-out"] = logout.cookie()
status, body = logout.call("GET", "/api/v3/flows/executor/default-invalidation-flow/?query=")
assert status == 200, (status, body)
# Moved: run.sh rewrites their stored last_ip, so the first request
# modifies and saves them (SessionStore.save) and refreshes the cookie.
cookies["session-moved-plain"] = Browser().login("m8-sess-plain").cookie()
cookies["session-moved-super"] = Browser().login("m8-sess-super").cookie()
cookies["session-moved-bearer"] = Browser().login("m8-sess-plain").cookie()
cookies["session-garbage"] = "not-a-jwt"
cookies["session-empty"] = ""
assert all(v is not None for v in cookies.values()), cookies
json.dump(cookies, sys.stdout)
