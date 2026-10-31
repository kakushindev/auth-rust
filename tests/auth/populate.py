"""Rows for the M5 request-identity differential: brands with tricky
domains, a tenant domain, and tokens and access tokens in every state the
bearer check distinguishes. Run with `python -m manage shell < populate.py`."""

from datetime import timedelta

from django.utils.timezone import now

from authentik.brands.models import Brand
from authentik.core.models import Token, TokenIntents, User, UserTypes
from authentik.flows.models import Flow
from authentik.providers.oauth2.models import AccessToken, OAuth2Provider
from authentik.tenants.models import Domain, Tenant

for domain in ["auth.test", "sub.auth.test", "a_b.test", "pct%x.test", "UPPER.test", "port.test:9000", "Ünï.test"]:
    Brand.objects.create(domain=domain, branding_title=domain)
Domain.objects.create(domain="tenant-a.test", tenant=Tenant.objects.get(schema_name="public"), is_primary=False)

active = User.objects.create(username="m5-active")
active.set_password("m5-password")
active.save()
inactive = User.objects.create(username="m5-inactive", is_active=False)
# Logged in over HTTP by sessions.py, then deactivated.
deactivated = User.objects.create(username="m5-deactivate")
deactivated.set_password("m5-password")
deactivated.save()
# Outposts may override the client IP with an internal service account's token.
service = User.objects.create(username="m5-service", type=UserTypes.INTERNAL_SERVICE_ACCOUNT)
service_account = User.objects.create(username="m5-sa", type=UserTypes.SERVICE_ACCOUNT)
past, future = now() - timedelta(days=1), now() + timedelta(days=1)
for identifier, key, intent, user, expiring, expires in [
    ("m5-api-active", "m5-api-active", TokenIntents.INTENT_API, active, False, past),
    ("m5-api-expired", "m5-api-expired", TokenIntents.INTENT_API, active, True, past),
    ("m5-api-future", "m5-api-future", TokenIntents.INTENT_API, active, True, future),
    ("m5-api-nullexp", "m5-api-nullexp", TokenIntents.INTENT_API, active, True, None),
    ("m5-recovery", "m5-recovery", TokenIntents.INTENT_RECOVERY, active, False, future),
    ("m5-api-inactive", "m5-api-inactive", TokenIntents.INTENT_API, inactive, False, future),
    ("m5-api-dup-1", "m5-dup", TokenIntents.INTENT_API, active, False, future),
    ("m5-api-dup-2", "m5-dup", TokenIntents.INTENT_API, inactive, False, future),
    ("m5-service", "m5-service", TokenIntents.INTENT_API, service, False, future),
    ("m5-service-expired", "m5-service-expired", TokenIntents.INTENT_API, service, True, past),
    ("m5-service-recovery", "m5-service-recovery", TokenIntents.INTENT_RECOVERY, service, False, future),
    ("m5-sa", "m5-sa", TokenIntents.INTENT_API, service_account, False, future),
]:
    Token.objects.create(identifier=identifier, key=key, intent=intent, user=user, expiring=expiring, expires=expires)

provider = OAuth2Provider.objects.create(
    name="m5-oauth2",
    authorization_flow=Flow.objects.get(slug="default-provider-authorization-explicit-consent"),
    invalidation_flow=Flow.objects.get(slug="default-provider-invalidation-flow"),
)
for token, scope, user, expires, revoked in [
    ("m5-at-api", "openid goauthentik.io/api", active, future, False),
    ("m5-at-noapi", "openid profile", active, future, False),
    ("m5-at-apix", "goauthentik.io/apix", active, future, False),
    ("m5-at-upper", "GOAUTHENTIK.IO/API", active, future, False),
    ("m5-at-expired", "goauthentik.io/api", active, past, False),
    ("m5-at-revoked", "goauthentik.io/api", active, future, True),
    ("m5-at-inactive", "goauthentik.io/api", inactive, future, False),
    ("m5-at-tab", "openid\tgoauthentik.io/api", active, future, False),
]:
    AccessToken.objects.create(provider=provider, user=user, auth_time=now(), token=token, _id_token="{}", _scope=scope, expires=expires, revoked=revoked)
print("[populate] ok")
