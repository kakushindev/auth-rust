"""Populate a snapshot database with varied rows for the M4 model test.

Run inside an authentik 2026.2.7 server container:
  python -m manage shell < tests/models/populate.py

Everything is created through Django's ORM, so the rows are exactly what
authentik writes. Values cover NULLs, unicode, JSON with unusual numerals
(1e-7, 20- and 30-digit integers, 3.0), nesting and emoji, arrays, IPs and binary
data. Each block reports `ok` or its error.
"""

import traceback
from datetime import timedelta

from django.utils.timezone import now

RESULTS = []


def block(name):
    def run(fn):
        try:
            fn()
            RESULTS.append((name, "ok"))
        except Exception as exc:  # noqa: BLE001 - report every failure
            where = traceback.extract_tb(exc.__traceback__)
            line = next((f for f in reversed(where) if f.filename == "<string>" or "populate" in f.filename), where[-1])
            RESULTS.append((name, f"{type(exc).__name__}: {exc} (line {line.lineno})".replace("\n", " ")))
        return fn

    return run


ODD_JSON = {
    "numbers": [1.10, 1e-7, 12345678901234567890, 123456789012345678901234567890, -0.0, 3.0],
    "text": "Gapura ✓ 🚪 ümlaut \"quoted\" \\ back\ttab",
    "nested": {"a": {"b": [None, True, False, {"c": []}]}},
    "empty": {},
}

from authentik.flows.models import Flow  # noqa: E402

AUTHZ = Flow.objects.get(slug="default-provider-authorization-explicit-consent")
INVALIDATION = Flow.objects.get(slug="default-provider-invalidation-flow")
PRE_AUTH = Flow.objects.get(slug="default-source-pre-authentication")
AUTHN = Flow.objects.get(slug="default-source-authentication")
ENROLL = Flow.objects.get(slug="default-source-enrollment")


@block("users and groups")
def _():
    from authentik.core.models import Group, User, UserTypes

    root = Group.objects.create(name="m4-root", attributes=ODD_JSON, is_superuser=False)
    child = Group.objects.create(name="m4-child ✓", attributes={})
    grandchild = Group.objects.create(name="m4-grandchild", attributes={"x": 1})
    child.parents.add(root)
    grandchild.parents.add(child, root)
    for i, kind in enumerate([UserTypes.INTERNAL, UserTypes.EXTERNAL, UserTypes.SERVICE_ACCOUNT, UserTypes.INTERNAL_SERVICE_ACCOUNT]):
        user = User.objects.create(
            username=f"m4-user-{i}-ü",
            name=f"M4 Üser {i} 🚪",
            email=f"m4-{i}@example.test" if i % 2 == 0 else "",
            type=kind,
            path="users/m4" if i else "users",
            attributes=ODD_JSON if i == 0 else {"i": i},
            is_active=i != 3,
            last_login=now() - timedelta(days=i) if i % 2 else None,
        )
        user.set_password(f"m4-password-{i}")
        user.save()
        user.ak_groups.add(grandchild if i % 2 else root)


@block("applications and entitlements")
def _():
    from authentik.core.models import Application, ApplicationEntitlement

    for i in range(3):
        app = Application.objects.create(
            name=f"M4 App {i} ✓",
            slug=f"m4-app-{i}",
            group="m4" if i else "",
            meta_launch_url=f"https://app{i}.example.test/" if i else "",
            meta_description="désc 🚪" if i == 1 else "",
            open_in_new_tab=bool(i % 2),
            policy_engine_mode="all" if i else "any",
        )
        ApplicationEntitlement.objects.create(name=f"m4-ent-{i}", app=app, attributes=ODD_JSON if i == 0 else {})


@block("tokens")
def _():
    from authentik.core.models import Token, TokenIntents, User

    user = User.objects.get(username="m4-user-0-ü")
    for i, intent in enumerate([TokenIntents.INTENT_API, TokenIntents.INTENT_APP_PASSWORD, TokenIntents.INTENT_RECOVERY, TokenIntents.INTENT_VERIFICATION]):
        Token.objects.create(
            identifier=f"m4-token-{i}",
            user=user,
            intent=intent,
            description="tökén" if i else "",
            expiring=bool(i % 2),
            expires=now() + timedelta(hours=i + 1),
        )


@block("providers")
def _():
    from authentik.core.models import Application
    from authentik.providers.ldap.models import LDAPProvider
    from authentik.providers.oauth2.models import OAuth2Provider, RedirectURI, RedirectURIMatchingMode, ScopeMapping
    from authentik.providers.proxy.models import ProxyMode, ProxyProvider
    from authentik.providers.rac.models import RACPropertyMapping, RACProvider
    from authentik.providers.radius.models import RadiusProvider, RadiusProviderPropertyMapping
    from authentik.providers.saml.models import SAMLPropertyMapping, SAMLProvider
    from authentik.providers.scim.models import SCIMMapping, SCIMProvider

    common = {"authorization_flow": AUTHZ, "invalidation_flow": INVALIDATION}
    scope = ScopeMapping.objects.create(name="m4-scope", scope_name="m4", expression="return {}")
    oauth = OAuth2Provider.objects.create(
        name="m4-oauth2",
        client_id="m4-client",
        client_secret="sëcret",
        redirect_uris=[
            RedirectURI(RedirectURIMatchingMode.STRICT, "https://m4.example.test/cb"),
            RedirectURI(RedirectURIMatchingMode.REGEX, "https://.*\\.example\\.test/"),
        ],
        **common,
    )
    oauth.property_mappings.add(scope)
    ProxyProvider.objects.create(
        name="m4-proxy",
        external_host="https://proxy.example.test",
        internal_host="http://internal:8080",
        mode=ProxyMode.FORWARD_SINGLE,
        skip_path_regex="^/health$",
        **common,
    )
    LDAPProvider.objects.create(name="m4-ldap", base_dn="DC=m4,DC=test", **common)
    radius = RadiusProvider.objects.create(name="m4-radius", shared_secret="s", client_networks="0.0.0.0/0, ::/0", **common)
    radius.property_mappings.add(RadiusProviderPropertyMapping.objects.create(name="m4-radius-pm", expression="return {}"))
    saml = SAMLProvider.objects.create(name="m4-saml", acs_url="https://sp.example.test/acs", issuer="m4", **common)
    saml.property_mappings.add(SAMLPropertyMapping.objects.create(name="m4-saml-pm", saml_name="n", expression="return 1"))
    scim = SCIMProvider.objects.create(name="m4-scim", url="https://scim.example.test/v2", token="t", **common)
    scim.property_mappings.add(SCIMMapping.objects.create(name="m4-scim-pm", expression="return {}"))
    RACProvider.objects.create(name="m4-rac", settings=ODD_JSON, **common)
    RACPropertyMapping.objects.create(name="m4-rac-pm", static_settings={"k": 1.10}, expression="")
    Application.objects.filter(slug="m4-app-0").update(provider=oauth)


@block("provider runtime rows")
def _():
    from django.contrib.sessions.backends.db import SessionStore

    from authentik.core.models import AuthenticatedSession, Session, User
    from authentik.providers.oauth2.models import AccessToken, AuthorizationCode, DeviceToken, OAuth2Provider, RefreshToken
    from authentik.providers.proxy.models import ProxySession
    from authentik.providers.rac.models import ConnectionToken, Endpoint, RACProvider
    from authentik.providers.saml.models import SAMLProvider, SAMLSession
    from authentik.providers.scim.models import SCIMProvider, SCIMProviderGroup, SCIMProviderUser
    from authentik.core.models import Group

    user = User.objects.get(username="m4-user-0-ü")
    oauth = OAuth2Provider.objects.get(name="m4-oauth2")
    session = Session.objects.create(
        session_key="m4session0000000000000000000000",
        session_data=b"\x00\x01binary\xff",
        last_ip="203.0.113.7",
        last_user_agent="Mozilla/5.0 (M4) ✓",
        last_used=now(),
        expires=now() + timedelta(days=1),
    )
    Session.objects.create(
        session_key="m4session6000000000000000000006",
        session_data=b"",
        last_ip="2001:db8::7",
        last_user_agent="",
        last_used=now(),
        expires=now() + timedelta(days=1),
    )
    auth_session = AuthenticatedSession.objects.create(session=session, user=user)
    AccessToken.objects.create(provider=oauth, user=user, auth_time=now(), token="m4-access", _id_token="{}", _scope="openid profile", session=auth_session)
    RefreshToken.objects.create(provider=oauth, user=user, auth_time=now(), token="m4-refresh", _id_token="{}", _scope="openid")
    AuthorizationCode.objects.create(provider=oauth, user=user, auth_time=now(), code="m4-code", nonce="n", _scope="openid", code_challenge="c", code_challenge_method="S256")
    DeviceToken.objects.create(provider=oauth, user_code="M4CODE", _scope="openid")
    ProxySession.objects.create(session_key="m4-proxy-session", user_id=user.pk, session_data={"a": 1.10}, expires=now())
    rac = RACProvider.objects.get(name="m4-rac")
    endpoint = Endpoint.objects.create(name="m4-endpoint", host="rdp.example.test:3389", protocol="rdp", auth_mode="static", provider=rac, settings=ODD_JSON)
    ConnectionToken.objects.create(provider=rac, endpoint=endpoint, session=auth_session, settings={"x": "y"})
    SAMLSession.objects.create(provider=SAMLProvider.objects.get(name="m4-saml"), user=user, session=auth_session, session_index="idx", name_id="m4@example.test", created=now(), expires=now())
    scim = SCIMProvider.objects.get(name="m4-scim")
    SCIMProviderUser.objects.create(scim_id="m4-scim-user", user=user, provider=scim, attributes=ODD_JSON)
    SCIMProviderGroup.objects.create(scim_id="m4-scim-group", group=Group.objects.get(name="m4-root"), provider=scim, attributes={})


@block("sources and connections")
def _():
    from authentik.core.models import Group, User
    from authentik.sources.kerberos.models import GroupKerberosSourceConnection, KerberosSource, KerberosSourcePropertyMapping, UserKerberosSourceConnection
    from authentik.sources.ldap.models import GroupLDAPSourceConnection, LDAPSource, LDAPSourcePropertyMapping, UserLDAPSourceConnection
    from authentik.sources.oauth.models import GroupOAuthSourceConnection, OAuthSource, OAuthSourcePropertyMapping, UserOAuthSourceConnection
    from authentik.sources.plex.models import GroupPlexSourceConnection, PlexSource, PlexSourcePropertyMapping, UserPlexSourceConnection
    from authentik.sources.saml.models import GroupSAMLSourceConnection, SAMLSource, SAMLSourcePropertyMapping, UserSAMLSourceConnection
    from authentik.sources.scim.models import SCIMSource, SCIMSourceGroup, SCIMSourcePropertyMapping, SCIMSourceUser
    from authentik.sources.telegram.models import GroupTelegramSourceConnection, TelegramSource, TelegramSourcePropertyMapping, UserTelegramSourceConnection

    user = User.objects.get(username="m4-user-1-ü")
    group = Group.objects.get(name="m4-child ✓")
    flows = {"authentication_flow": AUTHN, "enrollment_flow": ENROLL}
    sources = [
        (OAuthSource.objects.create(name="m4-oauth", slug="m4-oauth", provider_type="github", consumer_key="k", consumer_secret="s", additional_scopes="read:user", **flows), UserOAuthSourceConnection, GroupOAuthSourceConnection, OAuthSourcePropertyMapping, {"access_token": "at", "expires": now()}),
        (SAMLSource.objects.create(name="m4-saml-src", slug="m4-saml-src", pre_authentication_flow=PRE_AUTH, issuer="m4", sso_url="https://idp.example.test/sso", **flows), UserSAMLSourceConnection, GroupSAMLSourceConnection, SAMLSourcePropertyMapping, {}),
        (LDAPSource.objects.create(name="m4-ldap-src", slug="m4-ldap-src", server_uri="ldaps://ldap.example.test", base_dn="dc=m4,dc=test", enabled=False, **flows), UserLDAPSourceConnection, GroupLDAPSourceConnection, LDAPSourcePropertyMapping, {}),
        (PlexSource.objects.create(name="m4-plex", slug="m4-plex", plex_token="p", allowed_servers=["s1", "s2 ✓"], **flows), UserPlexSourceConnection, GroupPlexSourceConnection, PlexSourcePropertyMapping, {"plex_token": "u"}),
        (TelegramSource.objects.create(name="m4-telegram", slug="m4-telegram", bot_username="m4bot", bot_token="b", pre_authentication_flow=PRE_AUTH, **flows), UserTelegramSourceConnection, GroupTelegramSourceConnection, TelegramSourcePropertyMapping, {}),
        (KerberosSource.objects.create(name="m4-kerberos", slug="m4-kerberos", realm="M4.TEST", krb5_conf="", sync_principal="", sync_password="", sync_keytab="", sync_ccache="", spnego_server_name="", spnego_keytab="", spnego_ccache="", enabled=False, **flows), UserKerberosSourceConnection, GroupKerberosSourceConnection, KerberosSourcePropertyMapping, {}),
    ]
    for source, user_conn, group_conn, mapping, extra in sources:
        user_conn.objects.create(user=user, source=source, identifier=f"m4-{source.slug}-id", **extra)
        group_conn.objects.create(group=group, source=source, identifier=f"m4-{source.slug}-gid")
        source.user_property_mappings.add(mapping.objects.create(name=f"m4-{source.slug}-pm", expression="return {}"))
    scim = SCIMSource.objects.create(name="m4-scim-src", slug="m4-scim-src")
    SCIMSourceUser.objects.create(external_id="m4-ext", user=user, source=scim, attributes=ODD_JSON, last_update=now())
    SCIMSourceGroup.objects.create(external_id="m4-gext", group=group, source=scim, attributes={}, last_update=now())
    SCIMSourcePropertyMapping.objects.create(name="m4-scim-src-pm", expression="return {}")


@block("remaining many-to-many links")
def _():
    from authentik.core.models import Group, Source
    from authentik.providers.oauth2.models import OAuth2Provider
    from authentik.providers.rac.models import Endpoint, RACPropertyMapping
    from authentik.providers.scim.models import SCIMMapping, SCIMProvider
    from authentik.sources.oauth.models import OAuthSource, OAuthSourcePropertyMapping

    oauth = OAuth2Provider.objects.get(name="m4-oauth2")
    other = OAuth2Provider.objects.create(name="m4-oauth2-federated", authorization_flow=AUTHZ, invalidation_flow=INVALIDATION)
    oauth.jwt_federation_sources.add(OAuthSource.objects.get(slug="m4-oauth"))
    oauth.jwt_federation_providers.add(other)
    Endpoint.objects.get(name="m4-endpoint").property_mappings.add(RACPropertyMapping.objects.get(name="m4-rac-pm"))
    scim = SCIMProvider.objects.get(name="m4-scim")
    scim.group_filters.add(Group.objects.get(name="m4-root"))
    scim.property_mappings_group.add(SCIMMapping.objects.create(name="m4-scim-group-pm", expression="return {}"))
    Source.objects.get(slug="m4-oauth").group_property_mappings.add(
        OAuthSourcePropertyMapping.objects.create(name="m4-oauth-group-pm", expression="return {}")
    )


@block("enterprise provider row (base tables must still decode)")
def _():
    from authentik.enterprise.providers.google_workspace.models import GoogleWorkspaceProvider

    GoogleWorkspaceProvider.objects.create(
        name="m4-google-workspace",
        delegated_subject="admin@example.test",
        credentials={"type": "service_account"},
        default_group_email_domain="example.test",
    )


@block("brands and tenant domains")
def _():
    from authentik.brands.models import Brand
    from authentik.crypto.models import CertificateKeyPair
    from authentik.tenants.models import Domain, Tenant

    cert = CertificateKeyPair.objects.first()
    brand = Brand.objects.create(domain="m4.example.test", branding_title="Gapura ✓", attributes=ODD_JSON, web_certificate=cert)
    brand.client_certificates.add(cert)
    Domain.objects.create(domain="m4-tenant.example.test", tenant=Tenant.objects.get(schema_name="public"), is_primary=False)


for name, result in RESULTS:
    print(f"[populate] {name}: {result}")
