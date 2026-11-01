"""API tokens for the M7 read-API differential.

Run inside an authentik 2026.2.7 server container after tests/models/populate.py
and tests/rbac/populate.py:
  python -m manage shell < tests/api/populate.py

Every M6 subject (and akadmin) gets a non-expiring API token whose key is
"m7-<username>". Extra tokens cover the edges the read API must decline or
answer like Django: an expired token (Django deletes it while looking it up),
a recovery-intent token, and the inactive user's token.
"""

from datetime import timedelta

from django.db import transaction
from django.utils.timezone import now

from authentik.core.models import Token, TokenIntents, User

transaction.set_autocommit(False)
subjects = [u for u in User.objects.filter(username__startswith="m6-")] + [
    User.objects.get(username="akadmin")
]
for user in subjects:
    Token.objects.create(
        identifier=f"m7-{user.username}", key=f"m7-{user.username}", user=user,
        intent=TokenIntents.INTENT_API, expiring=False,
    )
admin = User.objects.get(username="akadmin")
Token.objects.create(
    identifier="m7-expired", key="m7-expired", user=admin, intent=TokenIntents.INTENT_API,
    expiring=True, expires=now() - timedelta(days=1),
)
Token.objects.create(
    identifier="m7-recovery", key="m7-recovery", user=admin,
    intent=TokenIntents.INTENT_RECOVERY, expiring=False,
)
# JSON escaping: quotes, backslashes, control characters, non-ASCII.
from authentik.rbac.models import Role  # noqa: E402

Role.objects.create(name='m7-weird "q" \\ \x01\x1f\x7f \u00e9 \u2028 \U0001f600')
# InitialPermissions (tests/models creates none): several permissions, none,
# one; the second carries an object-level view grant for role m6-object.
from django.contrib.auth.models import Permission  # noqa: E402

from authentik.rbac.models import InitialPermissions  # noqa: E402

role_model = Role.objects.get(name="m6-model")
perms = list(Permission.objects.filter(content_type__app_label="authentik_core").order_by("id")[:4])
ip_many = InitialPermissions.objects.create(name="m7-initial-many", role=role_model)
ip_many.permissions.set(perms)
ip_none = InitialPermissions.objects.create(name="m7-initial-none", role=role_model)
ip_one = InitialPermissions.objects.create(
    name='m7-initial "one" \u00e9', role=Role.objects.get(name="m6-object")
)
ip_one.permissions.set(perms[:1])
Role.objects.get(name="m6-object").assign_perms("authentik_rbac.view_initialpermissions", ip_none)
# Brands: every filterable relation set on some row, two client
# certificates, a duplicated domain (not unique in the database), floats and
# escapes in attributes, and an object-level view grant.
from authentik.brands.models import Brand  # noqa: E402
from authentik.crypto.models import CertificateKeyPair  # noqa: E402
from authentik.flows.models import Flow  # noqa: E402

certs = list(CertificateKeyPair.objects.order_by("name")[:2])
flows = {f.slug: f for f in Flow.objects.all()}
full = Brand.objects.create(
    domain="m7-full.test",
    branding_title='m7 "full" \u00e9',
    branding_logo="/static/m7/logo.svg",
    branding_favicon="/static/m7/favicon.ico",
    branding_custom_css=".m7 { color: red; }\n",
    branding_default_flow_background="/static/m7/bg.jpg",
    flow_authentication=flows["default-authentication-flow"],
    flow_invalidation=flows["default-invalidation-flow"],
    flow_user_settings=flows["default-user-settings-flow"],
    web_certificate=certs[0],
    attributes={"f": 1.5, "e": 0.000001, "u": 18446744073709551615, "n": None, "s": "\u2028 \x01", "nested": {"z": 1, "a": [0.1]}},
)
full.client_certificates.set(certs)
one = Brand.objects.create(domain="m7-one.test", branding_title="m7 one", attributes={})
one.client_certificates.set(certs[-1:])
Brand.objects.create(domain="m7-dup.test", branding_title="m7 dup a", web_certificate=certs[-1])
Brand.objects.create(domain="m7-dup.test", branding_title="m7 dup b")
Role.objects.get(name="m6-object").assign_perms("authentik_brands.view_brand", one)
# Notification transports in every mode, with and without webhook mappings.
from authentik.events.models import (  # noqa: E402
    NotificationTransport,
    NotificationWebhookMapping,
    TransportMode,
)

body = NotificationWebhookMapping.objects.create(name="m7-body", expression="return {}")
headers = NotificationWebhookMapping.objects.create(name="m7-headers", expression="return {}")
NotificationTransport.objects.create(
    name="m7-webhook", mode=TransportMode.WEBHOOK, webhook_url="https://hooks.example.test/a_b%",
    webhook_mapping_body=body, webhook_mapping_headers=headers, send_once=True,
)
NotificationTransport.objects.create(
    name="m7-slack \u00e9", mode=TransportMode.WEBHOOK_SLACK, webhook_url="https://slack.example.test/x",
    webhook_mapping_body=body,
)
NotificationTransport.objects.create(
    name="m7-email", mode=TransportMode.EMAIL, email_subject_prefix="", send_once=True,
)
Role.objects.get(name="m6-object").assign_perms("authentik_events.view_notificationwebhookmapping", headers)
local = NotificationTransport.objects.create(name="m7-local", mode=TransportMode.LOCAL)
Role.objects.get(name="m6-object").assign_perms("authentik_events.view_notificationtransport", local)
# Certificate-key pairs: each generated algorithm, a certificate without
# its key, NULL metadata, a microsecond expiry and an object-level grant.
from datetime import UTC, datetime  # noqa: E402

from authentik.crypto.builder import CertificateBuilder, PrivateKeyAlg  # noqa: E402

generated = {}
for alg in [PrivateKeyAlg.RSA, PrivateKeyAlg.ECDSA, PrivateKeyAlg.ED25519]:
    builder = CertificateBuilder(f"m7-cert-{alg}")
    builder.alg = alg
    builder.build(subject_alt_names=["m7.example.test"], validity_days=30)
    generated[alg] = builder.save()
CertificateKeyPair.objects.create(
    name="m7-cert-nokey", certificate_data=generated[PrivateKeyAlg.ECDSA].certificate_data,
)
CertificateKeyPair.objects.filter(pk=generated[PrivateKeyAlg.ED25519].pk).update(
    cert_expiry=datetime(2030, 5, 6, 7, 8, 9, 120, tzinfo=UTC)
)
bare = CertificateKeyPair.objects.create(
    name='m7-cert "bare" \u00e9', certificate_data=generated[PrivateKeyAlg.RSA].certificate_data,
)
CertificateKeyPair.objects.filter(pk=bare.pk).update(
    cert_expiry=None, cert_subject=None, fingerprint_sha256=None, fingerprint_sha1=None,
    key_type=None, managed="m7-managed",
)
Role.objects.get(name="m6-object").assign_perms(
    "authentik_crypto.view_certificatekeypair", generated[PrivateKeyAlg.ECDSA]
)
# Users for UserSerializer: initials from several name shapes, an
# attribute avatar (the tenant tries attributes.m7.avatar first), a
# non-dict path in that walk, and group and role memberships.
from authentik.core.models import Group  # noqa: E402
from authentik.tenants.models import Tenant  # noqa: E402

Tenant.objects.filter(schema_name="public").update(avatars="attributes.m7.avatar,gravatar,initials")
m7_group = Group.objects.create(name="m7-group", attributes={"g": 1.5})
for username, name, attributes in [
    ("m7-user-a", "Ada  Lovelace Byron", {}),
    ("m7-user-b", "\u00df\u00e9 x", {"m7": {"avatar": "https://img.example.test/a.png"}}),
    ("m7-user-c", "", {"m7": {"avatar": ""}}),
    ("m7-user-d", "  ", {"m7": {}}),
    ("m7-user-e", "&lt; <b>", {"m7": "plain"}),
    ("m7-user-f", "\u03a3\u039f\u03a6\u039f\u03a3 one", {"upn": "u@example.test"}),
]:
    u = User.objects.create(username=username, name=name, attributes=attributes, path="users/m7")
    u.groups.add(m7_group)
    if username in ("m7-user-a", "m7-user-b"):
        u.groups.add(Group.objects.get(name="m6-g-super-child"))
        u.roles.add(Role.objects.get(name="m6-model"), Role.objects.get(name="m6-object"))
Role.objects.get(name="m6-object").assign_perms(
    "authentik_core.view_user", User.objects.get(username="m7-user-c")
)
# Events with a fixed action/app, so their lists do not change while the
# stacks log their own events: JSON lookups on context, user and brand.
from authentik.events.models import Event  # noqa: E402

for i, (context, user, brand, ip) in enumerate([
    ({"model": {"pk": "0a1b2c", "app": "authentik_core", "model_name": "user", "name": "x"}}, {"pk": 1, "username": "m7-ev"}, {"name": "m7-brand"}, "10.0.0.1"),
    ({"model": {"pk": 12, "app": "authentik_rbac", "model_name": "role"}}, {"username": "akadmin"}, {}, None),
    ({"username": "m7-ctx", "authorized_application": {"pk": "app-1"}, "f": 1.25}, {}, {"name": "m7-brand"}, "10.0.0.2"),
    ({"http_request": {"path": "/m7", "args": {"q": ["\u00e9"]}}}, {"username": "m7-ev"}, {"pk": "b"}, "2001:db8::1"),
]):
    Event.objects.create(action="custom_m7", app=f"m7.app.{i % 2}", context=context, user=user, brand=brand, client_ip=ip)
# Notifications: one per severity, with and without an event and links,
# for akadmin and m6-direct (the owner filter).
from authentik.events.models import Notification  # noqa: E402

ev = Event.objects.filter(action="custom_m7").order_by("app", "event_uuid").first()
for i, (username, severity, event, link) in enumerate([
    ("akadmin", "notice", ev, "https://example.test/n?a=1&b=\u00e9"),
    ("akadmin", "alert", None, None),
    ("m6-direct", "warning", ev, None),
    ("m6-direct", "notice", None, ""),
]):
    Notification.objects.create(
        user=User.objects.get(username=username), severity=severity, body=f"m7 body {i} \"q\"",
        event=event, hyperlink=link, hyperlink_label="open" if link else None, seen=i % 2 == 1,
    )
# Notification rules: with a destination group (nested GroupSerializer),
# without one, with several transports, and an object-level grant.
from authentik.events.models import NotificationRule  # noqa: E402

rule_a = NotificationRule.objects.create(name="m7-rule-a", severity="alert", destination_group=m7_group)
rule_a.transports.set(NotificationTransport.objects.filter(name__startswith="m7-"))
NotificationRule.objects.create(name="m7-rule-b", severity="notice", destination_event_user=True)
rule_c = NotificationRule.objects.create(
    name="m7-rule-c", severity="warning", destination_group=Group.objects.get(name="m6-g-super-child")
)
Role.objects.get(name="m6-object").assign_perms("authentik_events.view_notificationrule", rule_c)
# Entitlements: one name on two applications (name is unique per app, so
# ordering by name ties), attributes, and an object-level grant.
from authentik.core.models import Application, ApplicationEntitlement  # noqa: E402

apps_m4 = list(Application.objects.order_by("slug")[:2])
for app in apps_m4:
    ApplicationEntitlement.objects.create(name="m7-ent-same", app=app, attributes={"m7": True})
granted = ApplicationEntitlement.objects.create(name="m7-ent-solo", app=apps_m4[0], attributes={"x": [1, 2.5]})
Role.objects.get(name="m6-object").assign_perms("authentik_core.view_applicationentitlement", granted)
# Users that log in over HTTP in sessions.py (M8 session reads): their
# password is a test value of this suite.
for username, group in [("m8-sess-plain", None), ("m8-sess-super", "m6-g-super"), ("m8-sess-inactive", None)]:
    u = User.objects.create(username=username, name=username, path="users/m8")
    u.set_password("m8-test-password")
    u.save()
    if group:
        u.groups.add(Group.objects.get(name=group))
transaction.commit()
print(f"[populate] tokens for {len(subjects)} subjects")
print("[populate] ok")
