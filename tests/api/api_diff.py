#!/usr/bin/env python3
"""M7 read-API differential: the same GET against reference, second
reference (noise floor) and candidate, for every subject token and every
query-parameter edge of each ported endpoint.

Buckets and comparison come from tests/differential/http/harness.py. A case
is only "equal" when status, headers (after the harness's narrow
normalization) and the JSON body match. Every endpoint also gets a check
that the candidate really answered from Rust: tests/api/run.sh starts the
candidate with AUTHENTIK_RS_API_TRACE=1, which adds `X-Authentik-Rs: <route>`
to Rust-served responses; that header is removed before comparison and
counted, so a silent fall-back to Django cannot pass as coverage.
"""

import argparse
import concurrent.futures
import json
import os
import pathlib
import sys
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/differential/http"))
import harness  # noqa: E402

REF, REF2, CAND = "http://127.0.0.1:29000", "http://127.0.0.1:29200", "http://127.0.0.1:29100"
TRACE = "x-authentik-rs"

SUBJECTS = [
    "m6-none",
    "m6-direct",
    "m6-grandchild",
    "m6-child-direct",
    "m6-dup",
    "m6-super",
    "m6-super-sub",
    "m6-inactive",
    "m6-inactive-super",
    "m6-service",
    "m6-service-none",
    "m6-broken",
    "akadmin",
]


def admin_get(path):
    status, _, body = harness.fetch(REF, path, "m7-akadmin")
    assert status == 200, (path, status, body[:200])
    return json.loads(body)


def all_results(path):
    sep = "&" if "?" in path else "?"
    return admin_get(f"{path}{sep}page_size=1000")["results"]


def q(**params):
    return "?" + urllib.parse.urlencode(params) if params else ""


def role_cases():
    roles = all_results("/api/v3/rbac/roles/")
    users = {u["username"]: u["pk"] for u in all_results("/api/v3/core/users/?search=m6-")}
    groups = {g["name"]: g["pk"] for g in all_results("/api/v3/core/groups/?search=m6-g")}
    managed = sorted({r.get("managed") for r in roles if r.get("managed")} or {"x"})
    base = "/api/v3/rbac/roles/"
    lists = [
        "",
        q(page=2, page_size=3),
        q(page=0),
        q(page=-1),
        q(page="abc"),
        q(page="last"),
        q(page="2.0"),
        q(page=999),
        q(page_size=0),
        q(page_size=-1),
        q(page_size="abc"),
        q(page_size=" 4"),
        q(page_size=1000000),
        q(page_size=2, page=" 2"),
        q(ordering="-name"),
        q(ordering="pk"),
        q(ordering="-pk"),
        q(ordering="managed"),
        q(ordering="nope"),
        q(ordering="-name,pk"),
        q(ordering=" name , -pk "),
        q(ordering=""),
        q(search="m6"),
        q(search="M6-D"),
        q(search="dup a"),
        q(search="m6,dup"),
        q(search='"m6-dup"'),
        q(search="%"),
        q(search="_"),
        q(search=""),
        q(search="é"),
        q(name="m6-model"),
        q(name="nope"),
        q(name=""),
        q(managed=managed[0]),
        q(managed="bogus"),
        "?managed=" + urllib.parse.quote(managed[0]) + "&managed=bogus",
        q(managed__isnull="true"),
        q(managed__isnull="false"),
        q(managed__isnull="garbage"),
        q(managed__isnull="True"),
        q(managed__isnull="1"),
        q(users=users["m6-direct"]),
        q(users=users["m6-grandchild"], inherited="true"),
        q(users=users["m6-grandchild"], inherited="false"),
        q(users=users["m6-child-direct"], inherited="TRUE"),
        q(users="abc"),
        q(users="1.5"),
        q(users=999999),
        q(users=""),
        q(groups=groups["m6-g-child"]),
        q(groups=groups["m6-g-grandchild"], inherited="true"),
        q(groups="00000000-0000-0000-0000-000000000000"),
        q(groups=""),
        q(search="m6", ordering="-name", page_size=2, page=2),
        q(unknown="1"),
        q(search="a\x00b"),
        q(name="a\x00b"),
        q(groups="a\x00b"),
        q(groups="not-a-uuid"),
        q(groups="{" + groups["m6-g-child"].upper() + "}"),
        q(users="1e0"),
        q(users=" 1 "),
        q(users="Infinity"),
        q(users="NaN"),
        q(users="-1"),
        q(users="99999999999"),
        q(users="1e400"),
        q(users="1e50"),
        q(users="1e51"),
        q(users="-1e400"),
        q(users="100000000000000007629769841091887003294964970946560"),
        q(users="100000000000000007629769841091887003294964970946560.5"),
        q(users="0.0012e3"),
        q(users="1_0"),
        q(users=" "),
        q(managed="None"),
        q(managed="null"),
        q(managed=""),
        "?managed=bogus&users=abc&name=a%00b",
        "?ordering=pk&ordering=-name",
        "?page=2&page=1&page_size=3",
        "?page_size=3&page_size=abc",
        q(search="m7-weird"),
        q(page_size="+3"),
        q(page="\u0663"),
        q(page_size="\u0663"),
        q(inherited="true"),
        "?" + "&".join(["x=1"] * 1001),
    ]
    cases = [(base + suffix) for suffix in lists]
    for role in roles:
        cases.append(f"{base}{role['pk']}/")
    cases += [
        f"{base}{roles[0]['pk'].replace('-', '')}/",
        f"{base}urn:uuid:{roles[0]['pk']}/",
        f"{base}{roles[0]['pk'][:-1]}g/",
        f"{base}{roles[0]['pk']}/{q(users=999999)}",
        f"{base}{roles[0]['pk']}/{q(managed='bogus')}",
        f"{base}00000000-0000-0000-0000-000000000000/",
        f"{base}not-a-uuid/",
        f"{base}{roles[0]['pk']}/{q(search='zzz-no-match')}",
        f"{base}{roles[0]['pk']}/{q(page='abc')}",
        f"{base}{roles[0]['pk'].upper()}/",
    ]
    return cases


def all_pages(path):
    out, page = [], 1
    while True:
        sep = "&" if "?" in path else "?"
        data = admin_get(f"{path}{sep}page_size=100&page={page}")
        out += data["results"]
        if not data["pagination"]["next"]:
            return out
        page += 1


def permission_cases():
    perms = all_pages("/api/v3/rbac/permissions/")
    roles = {r["name"]: r["pk"] for r in all_results("/api/v3/rbac/roles/")}
    total_pages = (len(perms) + 99) // 100
    base = "/api/v3/rbac/permissions/"
    names = {}
    for perm in perms:
        names.setdefault(perm["name"], []).append(perm["id"])
    dup_ids = [i for ids in names.values() if len(ids) > 1 for i in ids]
    lists = [""]
    lists += [q(page_size=100, page=n) for n in range(1, total_pages + 1)]
    lists += [q(page_size=7, page=n) for n in (1, 2, 50, 99, 100)]
    lists += [
        q(page="last", page_size=7),
        q(page_size=1000),
        q(ordering="-name", page_size=100),
        q(ordering="id"),
        q(ordering="-id", page_size=50, page=3),
        q(ordering="codename", page_size=100, page=4),
        q(ordering="content_type__model", page_size=100, page=2),
        q(ordering="-content_type__app_label,id", page_size=100),
        q(ordering="model"),
        q(ordering="app_label_verbose"),
        q(search="view"),
        q(search="can view", page_size=100),
        q(search="authentik_core"),
        q(search="USER"),
        q(search='"Can view"'),
        q(search="token's"),
        q(search="a\x00b"),
        q(codename="view_role"),
        q(codename=" view_role "),
        q(content_type__model="role"),
        q(content_type__app_label="authentik_rbac"),
        q(codename="view_role", content_type__model="role", content_type__app_label="authentik_rbac"),
        q(codename="a\x00b"),
        q(role=roles["m6-model"]),
        q(role=roles["m6-parent"], search="view"),
        q(role="bogus"),
        q(role="00000000-0000-0000-0000-000000000000"),
        q(role=""),
        "?codename=a%00b&role=bogus",
        q(content_type__app_label="auth"),
        q(unknown="1"),
    ]
    cases = [base + suffix for suffix in lists]
    for perm in perms[:5] + perms[-5:]:
        cases.append(f"{base}{perm['id']}/")
    cases += [f"{base}{i}/" for i in dup_ids]
    first = perms[0]["id"]
    cases += [
        f"{base}abc/",
        f"{base}%20{first}/",
        f"{base}+{first}/",
        f"{base}0/",
        f"{base}-1/",
        f"{base}99999999999/",
        f"{base}{first}/{q(role='bogus')}",
        f"{base}{first}/{q(codename='nope')}",
        f"{base}{first}/{q(search='zzz')}",
    ]
    # Viewsets the router registers under this prefix before it.
    cases += [
        "/api/v3/rbac/permissions/roles/",
        "/api/v3/rbac/permissions/assigned_by_roles/",
    ]
    return cases


def initial_permission_cases():
    rows = all_results("/api/v3/rbac/initial_permissions/")
    base = "/api/v3/rbac/initial_permissions/"
    lists = [
        "",
        q(page_size=1, page=2),
        q(page="last", page_size=2),
        q(page=9),
        q(ordering="pk"),
        q(ordering="-pk"),
        q(ordering="-name"),
        q(ordering="role,-pk"),
        q(ordering="permissions"),
        q(ordering="-permissions_obj"),
        q(search="m7"),
        q(search='"initial \\"one"'),
        q(search="initial one"),
        q(search="a\x00b"),
        q(name="m7-initial-many"),
        q(name=" m7-initial-none "),
        q(name="a\x00b"),
        q(name="nope"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [
        f"{base}abc/",
        f"{base}0/",
        f"{base}99999999999/",
        f"{base}{rows[0]['pk']}/{q(ordering='permissions')}",
        f"{base}{rows[0]['pk']}/{q(name='nope')}",
        f"{base}{rows[0]['pk']}/{q(search='a\x00b')}",
    ]
    return cases


def brand_cases():
    base = "/api/v3/core/brands/"
    rows = all_pages(base + "?domain=m7-full.test") + all_pages(base + "?default=true")
    rows += all_pages(base + "?search=m7-")
    full = next(r for r in rows if r["domain"] == "m7-full.test")
    default = next(r for r in rows if r["default"])
    certs = full["client_certificates"]
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(page_size=1),
        q(page_size=1, page=3),
        q(page_size=2, page=3),
        q(page="last", page_size=2),
        q(page=99),
        q(ordering="-domain", page_size=4),
        q(ordering="-domain,branding_title", page_size=4),
        q(ordering="default,-domain", page_size=3),
        q(ordering="branding_title", search="m7"),
        q(ordering="flow_authentication,domain", search="m7"),
        q(ordering="-web_certificate,domain", search="m7"),
        q(ordering="attributes", search="m7"),
        q(ordering="client_certificates"),
        q(ordering="-brand_uuid", search="m7"),
        q(ordering="bogus", search="m7"),
        q(search="m7"),
        q(search="m7 dup"),
        q(search='"m7 dup"'),
        q(search="Self-signed"),
        q(search="internal jwt"),
        q(search="nothing-matches"),
        q(search="a\x00b"),
        q(search="m7", default="false"),
        q(search="m7", client_certificates=certs[0]),
        q(search="Self-signed", web_certificate=certs[0]),
        q(brand_uuid=full["brand_uuid"]),
        q(brand_uuid=full["brand_uuid"].upper()),
        q(brand_uuid="bogus"),
        q(brand_uuid=" "),
        q(domain="m7-dup.test"),
        q(domain=" m7-one.test "),
        q(domain="a\x00b"),
        q(default="true"),
        q(default="True"),
        q(default="2"),
        q(default="1"),
        q(default="maybe"),
        q(default="false", search="m7"),
        q(default="3", search="m7"),
        q(default="0", search="m7"),
        q(default="TRUE"),
        q(default="FaLsE", search="m7"),
        q(branding_title="m7 one"),
        q(branding_logo="/static/m7/logo.svg"),
        q(branding_favicon="/static/m7/favicon.ico"),
        q(branding_default_flow_background="/static/m7/bg.jpg"),
        q(flow_authentication=full["flow_authentication"]),
        q(flow_invalidation=full["flow_invalidation"], domain="m7-full.test"),
        q(flow_user_settings=full["flow_user_settings"], search="m7"),
        q(flow_recovery=missing),
        q(flow_unenrollment="bogus"),
        q(flow_device_code="a\x00b"),
        q(web_certificate=certs[0], search="m7"),
        q(web_certificate=missing),
        q(client_certificates=certs[0]),
        q(client_certificates=certs[-1]),
        q(client_certificates=certs[0].upper()),
        q(client_certificates=missing),
        q(client_certificates="bogus"),
        "?" + urllib.parse.urlencode([("client_certificates", c) for c in certs]),
        "?" + urllib.parse.urlencode([("client_certificates", certs[0])] * 2),
        # Two invalid values: Django reports whichever comes first in a
        # frozenset (per-process hash order), so Rust declines.
        "?" + urllib.parse.urlencode([("client_certificates", certs[0]), ("domain", "m7-one.test")]),
        q(client_certificates=certs[0], page_size=1, page=2),
        q(brand_uuid="bogus", domain="a\x00b", flow_recovery="bogus"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['brand_uuid']}/" for r in rows if r["brand_uuid"] != default["brand_uuid"]]
    cases += [
        f"{base}{default['brand_uuid']}/",
        f"{base}{full['brand_uuid'].upper()}/",
        f"{base}{full['brand_uuid'].replace('-', '')}/",
        f"{base}{missing}/",
        f"{base}bogus/",
        f"{base}current/",
        f"{base}{full['brand_uuid']}/{q(domain='m7-one.test')}",
        f"{base}{full['brand_uuid']}/{q(brand_uuid='bogus')}",
        f"{base}{full['brand_uuid']}/{q(search='nothing-matches')}",
        f"{base}{full['brand_uuid']}/{q(client_certificates=certs[0])}",
    ]
    return cases


def transport_cases():
    base = "/api/v3/events/transports/"
    rows = all_pages(base)
    webhook = next(r for r in rows if r["name"] == "m7-webhook")
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(page_size=2),
        q(page_size=2, page=2),
        q(page="last", page_size=4),
        q(page=0),
        q(ordering="-name"),
        q(ordering="mode,name"),
        q(ordering="-send_once,name"),
        q(ordering="webhook_mapping_body,name"),
        q(ordering="-webhook_mapping_headers,-name"),
        q(ordering="email_subject_prefix,name"),
        q(ordering="email_template,-pk"),
        q(ordering="webhook_url,name"),
        q(ordering="mode_verbose"),
        q(ordering="-pk"),
        q(search="m7"),
        q(search="webhook"),
        q(search="a_b%"),
        q(search="EXAMPLE.test"),
        q(search="m7 slack"),
        q(search="\u00e9"),
        q(search="a\x00b"),
        q(name="m7-local"),
        q(name=" m7-local "),
        q(name="a\x00b"),
        q(mode="email"),
        q(mode="webhook_slack"),
        q(mode=" email"),
        q(mode="EMAIL"),
        q(mode="bogus"),
        q(mode="a\x00b"),
        q(mode=""),
        q(webhook_url="https://slack.example.test/x"),
        q(webhook_url=""),
        q(send_once="true"),
        q(send_once="False"),
        q(send_once="maybe"),
        q(send_once="1"),
        q(send_once="0"),
        q(send_once="2"),
        q(send_once="TRUE"),
        q(mode="bogus", name="a\x00b"),
        q(mode="local", send_once="true"),
        q(search="m7", mode="webhook", ordering="-name"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [
        f"{base}{webhook['pk'].upper()}/",
        f"{base}{missing}/",
        f"{base}bogus/",
        f"{base}{webhook['pk']}/{q(mode='local')}",
        f"{base}{webhook['pk']}/{q(mode='bogus')}",
        f"{base}{webhook['pk']}/used_by/",
    ]
    return cases


def webhook_mapping_cases():
    base = "/api/v3/propertymappings/notification/"
    rows = all_pages(base)
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(page_size=1, page=2),
        q(ordering="-name"),
        q(ordering="expression,-pk"),
        q(ordering="managed"),
        q(search="m7"),
        q(search="HEADERS"),
        q(search="a\x00b"),
        q(name="m7-body"),
        q(name=" m7-body "),
        q(name="a\x00b"),
        q(name="nope"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [f"{base}{missing}/", f"{base}bogus/", f"{base}{rows[0]['pk']}/{q(name='nope')}"]
    return cases


def certificate_cases():
    base = "/api/v3/crypto/certificatekeypairs/"
    rows = all_pages(base)
    rsa = next(r for r in rows if r["name"] == "m7-cert-rsa")
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(page_size=3),
        q(page_size=3, page=2),
        q(page="last", page_size=3),
        q(page="x"),
        q(ordering="-name"),
        q(ordering="cert_expiry,name"),
        q(ordering="-cert_expiry,name"),
        q(ordering="cert_subject,name"),
        q(ordering="key_type,-name"),
        q(ordering="-managed,name"),
        q(ordering="fingerprint_sha1"),
        q(ordering="-fingerprint_sha256"),
        q(ordering="private_key_available"),
        q(ordering="key_data"),
        q(ordering="-pk"),
        q(search="m7"),
        q(search="CERT-E"),
        q(search="bare"),
        q(search="a\x00b"),
        q(name="m7-cert-rsa"),
        q(name=" m7-cert-rsa "),
        q(name="a\x00b"),
        q(managed="m7-managed"),
        q(managed="goauthentik.io/crypto/jwt-managed"),
        q(managed=""),
        q(managed="a\x00b"),
        q(has_key="true"),
        q(has_key="false"),
        q(has_key="1"),
        q(has_key="x"),
        q(key_type="rsa"),
        q(key_type="ed25519"),
        q(key_type="RSA"),
        q(key_type=""),
        q(key_type="bogus"),
        "?" + urllib.parse.urlencode([("key_type", "rsa"), ("key_type", "ec")]),
        "?" + urllib.parse.urlencode([("key_type", "rsa"), ("key_type", "")]),
        "?" + urllib.parse.urlencode([("key_type", "rsa"), ("key_type", "x"), ("key_type", "y")]),
        q(has_key="true", key_type="ec", search="m7"),
        q(name="a\x00b", managed="a\x00b", key_type="y", has_key="x"),
        q(key_type="y", search="a\x00b"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [
        f"{base}{rsa['pk'].upper()}/",
        f"{base}{missing}/",
        f"{base}bogus/",
        f"{base}generate/",
        f"{base}{rsa['pk']}/{q(key_type='ec')}",
        f"{base}{rsa['pk']}/{q(key_type='x')}",
    ]
    return cases


def user_cases():
    base = "/api/v3/core/users/"
    rows = all_pages(base + "?search=m7-user") + all_pages(base + "?search=m6-")
    a = next(r for r in rows if r["username"] == "m7-user-a")
    groups = all_pages("/api/v3/core/groups/?search=m7-group&include_users=false")
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(page_size=1),
        q(search="m7-user"),
        q(search="m7-user", include_groups="false"),
        q(search="m7-user", include_groups="False", include_roles="0"),
        q(search="m7-user", include_roles="TRUE"),
        q(search="m7-user", page_size=2, page=2),
        q(search="m6-", page="last", page_size=3),
        q(search="m6-", ordering="-username"),
        q(search="m6-", ordering="is_active,-pk"),
        q(search="m7-user", ordering="name"),
        q(search="m7-user", ordering="-last_login,username"),
        q(search="m7-user", ordering="type,email,-uuid"),
        q(search="m7-user", ordering="path,password_change_date"),
        q(search="m7-user", ordering="is_superuser"),
        q(search="m7-user", ordering="uid"),
        q(search="m7-user", ordering="groups"),
        q(search="m7-user", ordering="avatar"),
        q(search="m7-user", ordering="attributes"),
        q(search=a["uuid"][:8]),
        q(search="LOVELACE"),
        q(search="a\x00b"),
        q(username="m7-user-a"),
        q(username=" m7-user-a "),
        q(email=""),
        q(name="Ada  Lovelace Byron"),
        q(is_active="true", search="m6-"),
        q(is_active="3", search="m6-"),
        q(is_active="1", search="m6-"),
        q(is_superuser="true"),
        q(is_superuser="false", search="m6-"),
        q(is_superuser="2", search="m7-user"),
        q(groups_by_name="m7-group"),
        q(groups_by_name="m6-g-super-child", search="m7"),
        q(groups_by_name="nope"),
        q(groups_by_name=""),
        q(groups_by_name="a\x00b"),
        "?" + urllib.parse.urlencode([("groups_by_name", "m7-group"), ("groups_by_name", "m6-g-super")]),
        q(groups_by_pk=groups[0]["pk"]) if groups else q(groups_by_pk=missing),
        q(groups_by_pk=missing),
        q(groups_by_pk="bogus"),
        q(roles_by_name="m6-model"),
        q(roles_by_name="nope"),
        q(roles_by_pk=a["roles"][0]),
        q(roles_by_pk="x"),
        q(type="internal", search="m7"),
        q(type="service_account"),
        q(type="bogus"),
        "?" + urllib.parse.urlencode([("type", "internal"), ("type", "external"), ("search", "m")]),
        "?" + urllib.parse.urlencode([("type", "internal"), ("type", "x")]),
        q(last_login__isnull="true", search="m7-user"),
        q(last_login__isnull="false"),
        q(uuid=a["uuid"]),
        q(uuid="nope"),
        q(path="users/m7"),
        q(path_startswith="users/m"),
        q(path_startswith="users_"),
        q(path_startswith="a\x00b"),
        q(date_joined__gt="2020-01-01T00:00:00Z", search="m7"),
        q(attributes='{"m7": {}}'),
        q(date_joined=" "),
        q(username="a\x00b", groups_by_name="nope", type="x", uuid="y"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [
        f"{base}{a['pk']}/{q(include_groups='false', include_roles='false')}",
        f"{base}{a['pk']}/{q(groups_by_name='nope')}",
        f"{base}{a['pk']}/{q(search='zzz')}",
        f"{base}999999/",
        f"{base}abc/",
        f"{base}me/",
        f"{base}paths/",
        f"{base}{a['pk']}/used_by/",
    ]
    return cases


def group_cases():
    base = "/api/v3/core/groups/"
    rows = all_pages(base + "?search=m6-g") + all_pages(base + "?search=m7-group")
    sup = next(r for r in rows if r["name"] == "m6-g-super-child")
    member = all_results("/api/v3/core/users/?search=m6-super")[0]["pk"]
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(search="m6-g"),
        q(search="m6-g", page_size=2, page=2),
        q(search="m6-g", page="last", page_size=2),
        q(search="true"),
        q(search="m6-g", include_users="false"),
        q(search="m6-g", include_users="0", include_children="true"),
        q(search="m6-g", include_parents="TRUE", include_inherited_roles="true"),
        q(search="m6-g", include_children="1", include_parents="yes"),
        q(search="m7", include_inherited_roles="True", include_users="False"),
        q(search="m6-g", ordering="-name"),
        q(search="m6-g", ordering="is_superuser,name"),
        q(search="m6-g", ordering="-pk"),
        q(search="m6-g", ordering="num_pk"),
        q(search="m6-g", ordering="users"),
        q(search="m6-g", ordering="attributes"),
        q(search="a\x00b"),
        q(name="m6-g-super"),
        q(name=" m6-g-super "),
        q(name="a\x00b"),
        q(is_superuser="true"),
        q(is_superuser="3", search="m6"),
        q(is_superuser="1", search="m6"),
        q(members_by_pk=member),
        q(members_by_pk=f" {member}"),
        q(members_by_pk="x"),
        q(members_by_pk=""),
        q(members_by_pk="999999"),
        q(members_by_pk="99999999999"),
        "?" + urllib.parse.urlencode([("members_by_pk", member), ("members_by_pk", member)]),
        q(members_by_username="m6-super"),
        q(members_by_username="m7-user-a", include_inherited_roles="true"),
        q(members_by_username="nope"),
        q(members_by_username=""),
        "?" + urllib.parse.urlencode([("members_by_username", "m7-user-a"), ("members_by_pk", member)]),
        q(attributes='{"g": 1.5}'),
        q(name="a\x00b", members_by_pk="x", members_by_username="nope"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [
        f"{base}{sup['pk']}/{q(include_children='true', include_parents='true', include_inherited_roles='true')}",
        f"{base}{sup['pk']}/{q(include_users='false')}",
        f"{base}{sup['pk']}/{q(name='nope')}",
        f"{base}{sup['pk'].upper()}/",
        f"{base}{missing}/",
        f"{base}bogus/",
        f"{base}{sup['pk']}/used_by/",
    ]
    return cases


def token_cases():
    base = "/api/v3/core/tokens/"
    rows = all_pages(base + "?search=m7-")
    lists = [
        "",
        q(page_size=3),
        q(page_size=3, page=2),
        q(search="m7-m6"),
        q(search="m7", include_groups="false"),
        q(search="m7", include_roles="false", page_size=4),
        q(search="RECOVERY"),
        q(search="akadmin"),
        q(search="a\x00b"),
        q(search="m7", ordering="-identifier"),
        q(search="m7", ordering="user,-pk"),
        q(search="m7", ordering="-expires,identifier"),
        q(search="m7", ordering="intent,expiring,identifier"),
        q(search="m7", ordering="user_obj"),
        q(search="m7", ordering="key"),
        q(identifier="m7-akadmin"),
        q(identifier=" m7-akadmin "),
        q(identifier="a\x00b"),
        q(intent="recovery"),
        q(intent="api", search="m7-m6-s"),
        q(intent="API"),
        q(intent="bogus"),
        q(user__username="akadmin"),
        q(user__username="m6-direct", search="m7"),
        q(user__username="a\x00b"),
        q(description=""),
        q(expiring="true"),
        q(expiring="0", search="m7-m6"),
        q(expiring="2"),
        q(managed="x"),
        q(expires="2020-01-01T00:00:00Z"),
        q(intent="bogus", identifier="a\x00b"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['identifier']}/" for r in rows]
    cases += [
        f"{base}m7-akadmin/{q(include_groups='false', include_roles='false')}",
        f"{base}m7-akadmin/{q(intent='recovery')}",
        f"{base}m7-akadmin/{q(intent='bogus')}",
        f"{base}does-not-exist/",
        f"{base}M7-AKADMIN/",
        f"{base}m7-akadmin/used_by/",
    ]
    return cases


def event_cases():
    base = "/api/v3/events/events/"
    rows = all_pages(base + "?action=custom_m7")
    m7 = {"action": "custom_m7"}
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        q(**m7),
        q(**m7, page_size=1, page=2),
        q(**m7, page="last", page_size=3),
        q(**m7, ordering="created"),
        q(**m7, ordering="-app,created"),
        q(**m7, ordering="client_ip,created"),
        q(**m7, ordering="context"),
        q(**m7, ordering="-user,-created"),
        q(**m7, ordering="brand,created"),
        q(**m7, ordering="-pk"),
        q(**m7, search="m7-ev"),
        q(**m7, search="10.0.0"),
        q(**m7, search="2001:DB8"),
        q(**m7, search="M7.APP.1"),
        q(**m7, search="a\x00b"),
        q(action="CUSTOM_M"),
        q(**m7, client_ip="10.0.0.1"),
        q(**m7, client_ip="10.0.0.9"),
        q(**m7, client_ip="2001:db8::1"),
        q(**m7, client_ip="not-an-ip"),
        q(**m7, username="m7-ev"),
        q(**m7, username="m7-ctx"),
        q(**m7, username="akadmin"),
        q(**m7, context_model_pk="0a1b2c"),
        q(**m7, context_model_pk="0a-1b-2c"),
        q(**m7, context_model_pk="12"),
        q(**m7, context_model_pk=" 1-2 "),
        q(**m7, context_model_name="user"),
        q(**m7, context_model_app="authentik_rbac"),
        q(**m7, context_authorized_app="app-1"),
        q(**m7, brand_name="m7-brand"),
        q(**m7, actions="login"),
        q(actions="custom_", search="custom_m7"),
        q(**m7, actions="bogus"),
        "?" + urllib.parse.urlencode([("action", "custom_m7"), ("actions", "login"), ("actions", "x")]),
        q(**m7, username="a\x00b", actions="bogus", brand_name="a\x00b"),
        q(action="a\x00b"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [
        f"{base}{rows[0]['pk']}/{q(action='nope')}",
        f"{base}{rows[0]['pk']}/{q(actions='bogus')}",
        f"{base}{missing}/",
        f"{base}bogus/",
        f"{base}actions/",
    ]
    return cases


def notification_cases():
    base = "/api/v3/events/notifications/"
    rows = all_pages(base)
    ev = next((r["event"]["pk"] for r in rows if r["event"]), None)
    admin = all_results("/api/v3/core/users/?username=akadmin")[0]["pk"]
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(page_size=1),
        q(page_size=1, page=2),
        q(ordering="body"),
        q(ordering="-severity,body"),
        q(ordering="seen,body"),
        q(ordering="-created"),
        q(ordering="hyperlink,body"),
        q(ordering="event,body"),
        q(ordering="user"),
        q(search="m7"),
        q(search="a\x00b"),
        q(severity="alert"),
        q(severity="ALERT"),
        q(severity="nope"),
        q(body='m7 body 0 "q"'),
        q(body="a\x00b"),
        q(seen="true"),
        q(seen="0"),
        q(seen="3"),
        q(user=admin),
        q(user=f" {admin} "),
        q(user="abc"),
        q(user="999999"),
        q(user="a\x00b"),
        q(event=ev) if ev else q(event=missing),
        q(event=missing),
        q(event="bogus"),
        q(created="2020-01-01"),
        q(severity="nope", user="abc", event="bogus"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [f"{base}{missing}/", f"{base}bogus/", f"{base}mark_all_seen/"]
    return cases


def rule_cases():
    base = "/api/v3/events/rules/"
    rows = all_pages(base)
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        "",
        q(page_size=2, page=2),
        q(search="m7-rule"),
        q(search="m7-group"),
        q(search="authentik Admins"),
        q(search="m7", include_users="false"),
        q(search="m7", include_children="true", include_parents="true"),
        q(search="m7", include_inherited_roles="true"),
        q(search="a\x00b"),
        q(ordering="-name"),
        q(ordering="severity,name"),
        q(ordering="destination_group,name"),
        q(ordering="-destination_event_user,name"),
        q(ordering="transports"),
        q(ordering="destination_group_obj"),
        q(name="m7-rule-a"),
        q(name="a\x00b"),
        q(severity="alert"),
        q(severity="bogus"),
        q(destination_group__name="m7-group"),
        q(destination_group__name=" m7-group ", search="m7"),
        q(destination_group__name="nope", search="m7"),
        q(destination_group__name=" "),
        q(destination_group__name="a\x00b"),
        q(severity="bogus", name="a\x00b", destination_group__name="a\x00b"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pk']}/" for r in rows]
    cases += [
        f"{base}{rows[0]['pk']}/{q(include_users='false')}",
        f"{base}{rows[0]['pk']}/{q(severity='bogus')}",
        f"{base}{missing}/",
        f"{base}bogus/",
    ]
    return cases


def assigned_by_roles_cases():
    base = "/api/v3/rbac/permissions/assigned_by_roles/"
    admin = all_results("/api/v3/core/users/?username=akadmin")[0]["pk"]
    lists = [
        "",
        q(model="authentik_core.user"),
        q(model="authentik_core.user", object_pk=admin),
        q(model="authentik_core.user", object_pk=f" {admin} "),
        q(model="authentik_core.application"),
        q(model="authentik_rbac.initialpermissions", object_pk="1"),
        q(model="authentik_core.user", page_size=1, page=2),
        q(model="authentik_core.user", page_size=50),
        q(model="authentik_core.user", page_size=3),
        q(model="authentik_core.user", ordering="-name"),
        q(model="authentik_core.user", ordering="pk"),
        q(model="authentik_core.user", ordering="role_pk"),
        q(model="authentik_core.user", ordering="roleobjectpermission_set"),
        q(model="authentik_core.user", search="m6-o"),
        q(model="authentik_core.user", search="a\x00b"),
        q(model="AUTHENTIK_CORE.USER"),
        q(model=" authentik_core.user"),
        q(model="authentik_core.nope"),
        q(model="authentik_core.user", object_pk="a\x00b"),
        q(object_pk="1"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}x/", f"{base}x/assign/"]
    return cases


def entitlement_cases():
    base = "/api/v3/core/application_entitlements/"
    rows = all_pages(base + "?search=m7-ent")
    app = rows[0]["app"]
    missing = "00000000-0000-4000-8000-000000000000"
    lists = [
        q(search="m7-ent"),
        q(search="m7-ent", ordering="-name"),
        q(search="m7-ent", ordering="app,name"),
        q(search="m7-ent", ordering="pbm_uuid"),
        q(search="m7-ent", ordering="attributes"),
        q(search="m7-ent", page_size=1, page=2),
        q(search="true"),
        q(search="m4-app"),
        q(search="a\x00b"),
        q(name="m7-ent-same"),
        q(name="m7-ent-solo"),
        q(name="a\x00b"),
        q(pbm_uuid=rows[0]["pbm_uuid"]),
        q(pbm_uuid="bogus"),
        q(app=app),
        q(app=missing),
        q(app="bogus"),
        q(app=app, search="solo"),
        q(name="a\x00b", app="bogus", pbm_uuid="x"),
    ]
    cases = [base + suffix for suffix in lists]
    cases += [f"{base}{r['pbm_uuid']}/" for r in rows]
    cases += [f"{base}{missing}/", f"{base}bogus/", f"{base}{rows[0]['pbm_uuid']}/{q(name='nope')}"]
    return cases


ENDPOINTS = {
    "rbac_roles": role_cases,
    "rbac_permissions": permission_cases,
    "rbac_initial_permissions": initial_permission_cases,
    "core_brands": brand_cases,
    "events_transports": transport_cases,
    "propertymappings_notification": webhook_mapping_cases,
    "crypto_certificatekeypairs": certificate_cases,
    "core_users": user_cases,
    "core_groups": group_cases,
    "core_tokens": token_cases,
    "events_events": event_cases,
    "events_notifications": notification_cases,
    "events_rules": rule_cases,
    "rbac_permissions_assigned_by_roles": assigned_by_roles_cases,
    "core_application_entitlements": entitlement_cases,
}


def strip_trace(response):
    status, headers, body = response
    headers = {k: v for k, v in headers.items() if k != TRACE}
    return status, headers, body


# Session and CSRF variants (M8): a label instead of a token. Their cookie
# values come from sessions.py through $API_SESSIONS.
SESSIONS = json.loads(pathlib.Path(os.environ["API_SESSIONS"]).read_text()) if os.environ.get("API_SESSIONS") else {}
VARIANTS = {
    **{f"cookie:{k}": (None, f"authentik_session={v}") for k, v in SESSIONS.items()},
    **(
        {"cookie+bearer:session-plain+m7-akadmin": ("m7-akadmin", f"authentik_session={SESSIONS['session-plain']}")}
        if SESSIONS
        else {}
    ),
    "csrf:valid": ("m7-akadmin", "authentik_csrf=" + "a" * 32),
    "csrf:invalid": ("m7-akadmin", "authentik_csrf=not-valid!"),
}


def fetch(base, path, token):
    if token in VARIANTS:
        bearer, cookie = VARIANTS[token]
        return harness.fetch(base, path, bearer, extra={"Cookie": cookie})
    return harness.fetch(base, path, token)


def run_case(name, path, token):
    """One case: the same request to the three stacks, then the buckets."""
    ref = fetch(REF, path, token)
    ref2 = fetch(REF2, path, token)
    cand = fetch(CAND, path, token)
    rust = TRACE in cand[1]
    cand = strip_trace(cand)
    diffs = harness.compare(ref, cand)
    noise_kinds = {harness.kind(d) for d in harness.compare(ref, ref2)}
    if not diffs:
        bucket = "equal"
    elif all(harness.kind(d) in noise_kinds for d in diffs):
        bucket = "nondeterministic"
    else:
        bucket = "different"
    if bucket == "different":
        print(f"DIFF {token} {path}: " + "; ".join(diffs)[:600], flush=True)
    return {
        "endpoint": name,
        "path": path,
        "token": token,
        "status": ref[0],
        "rust": rust,
        "bucket": bucket,
        "diffs": diffs,
    }


def run_token(token, work):
    """Every case of one token, in suite order. Within a token the order is
    the sequential run's: a token's own side effects (Django deletes an
    expired token on first use) happen at the same point on every stack."""
    return [(index, run_case(name, path, token)) for index, name, path in work]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=None)
    ap.add_argument("--only", default=None, help="comma-separated endpoint names")
    ap.add_argument(
        "--jobs",
        type=int,
        default=int(os.environ.get("API_JOBS", "8")),
        help="tokens run concurrently (1 = the old fully sequential run)",
    )
    args = ap.parse_args()

    tokens = [None, "not-a-token", "m7-expired", "m7-recovery"] + [f"m7-{s}" for s in SUBJECTS]
    # Case lists read the reference through admin_get, so build them first,
    # in suite order.
    work = []
    for name, make in ENDPOINTS.items():
        if args.only and name not in args.only.split(","):
            continue
        work += [(name, path) for path in make()]
    indexed = [(i, name, path) for i, (name, path) in enumerate(work)]

    # Warm-up, sequential: each token's first case, so one-time effects
    # of a token (the expired one is deleted on first use) are settled on
    # all stacks before tokens interleave.
    # Session/CSRF variants exercise the middleware rather than the view:
    # every fifth case of each endpoint.
    sampled = []
    for name in dict.fromkeys(n for _, n, _ in indexed):
        mine = [c for c in indexed if c[1] == name]
        sampled += mine[::5]
    sampled.sort()
    plan = [(t, indexed) for t in tokens] + [(v, sampled) for v in VARIANTS]
    done = {}
    for t, (token, cases) in enumerate(plan):
        for index, case in run_token(token, cases[:1]):
            done[(index, t)] = case
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futures = {pool.submit(run_token, token, cases[1:]): t for t, (token, cases) in enumerate(plan)}
        for future in concurrent.futures.as_completed(futures):
            t = futures[future]
            for index, case in future.result():
                done[(index, t)] = case
    results = [done[key] for key in sorted(done)]

    served, buckets, statuses = {}, {}, {}
    for r in results:
        served[r["endpoint"]] = served.get(r["endpoint"], 0) + int(r["rust"])
        buckets[r["bucket"]] = buckets.get(r["bucket"], 0) + 1
        statuses[r["status"]] = statuses.get(r["status"], 0) + 1
    summary = {
        "cases": len(results),
        "buckets": dict(sorted(buckets.items())),
        "served_by_rust": served,
        "reference_status_histogram": dict(sorted(statuses.items())),
    }
    print(json.dumps(summary))
    if args.report:
        pathlib.Path(args.report).write_text(
            json.dumps({"summary": summary, "results": results}, indent=1) + "\n"
        )
    sys.exit(1 if buckets.get("different") else 0)


if __name__ == "__main__":
    main()
