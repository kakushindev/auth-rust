# Appended after `VECTORS = …` by run.sh, then run with `python -m manage shell`.
"""Django's decisions for every vector, as JSON: get_host, brand, tenant for
each host; bearer_auth for each Authorization header. Runs in a transaction
that is rolled back, since the token lookups delete expired rows."""

import base64
import json
from pathlib import Path
from tempfile import gettempdir

from django.conf import settings
from django.core.exceptions import DisallowedHost
from django.db import transaction
from django.test import RequestFactory
from rest_framework.exceptions import AuthenticationFailed

from authentik.api.authentication import IPCUser, TokenAuthentication
from authentik.brands.utils import DEFAULT_BRAND, get_brand_for_request
from authentik.core.models import Token
from authentik.outposts.models import Outpost
from authentik.providers.oauth2.models import AccessToken
from authentik.tenants.middleware import DefaultTenantMiddleware
from authentik.tenants.models import Domain

ipc_key = (Path(gettempdir()) / "authentik-core-ipc.key").read_text()
out = {"hosts": [], "headers": []}
with transaction.atomic():
    for host in VECTORS["hosts"]:  # noqa: F821
        request = RequestFactory().get("/", HTTP_HOST=host)
        row = {"host": host}
        try:
            row["get_host"] = request.get_host()
        except DisallowedHost:
            row["get_host"] = "DisallowedHost"
        try:
            brand = get_brand_for_request(request)
            row["brand"] = "fallback" if brand is DEFAULT_BRAND else str(brand.brand_uuid)
        except DisallowedHost:
            row["brand"] = "DisallowedHost"
        try:
            hostname = DefaultTenantMiddleware.hostname_from_request(request)
            row["tenant_hostname"] = hostname
            try:
                row["tenant"] = str(DefaultTenantMiddleware(lambda r: None).get_tenant(Domain, hostname).tenant_uuid)
            except Domain.DoesNotExist:
                row["tenant"] = "DoesNotExist"
        except DisallowedHost:
            row["tenant_hostname"] = row["tenant"] = "DisallowedHost"
        out["hosts"].append(row)
    for encoded in VECTORS["headers"]:  # noqa: F821
        raw = base64.b64decode(encoded).replace(b"{SECRET_KEY}", settings.SECRET_KEY.encode()).replace(b"{IPC_KEY}", ipc_key.encode())
        try:
            result = TokenAuthentication().bearer_auth(raw)
            if result is None:
                text = "none"
            else:
                user, ctx = result
                if isinstance(user, IPCUser):
                    text = "ipc"
                elif isinstance(ctx, Token):
                    text = f"api_token:{ctx.token_uuid}:{user.pk}"
                elif isinstance(ctx, AccessToken):
                    text = f"jwt:{ctx.id}:{user.pk}"
                elif isinstance(ctx, Outpost):
                    text = f"secret_key:{ctx.uuid}:{user.pk}"
                else:
                    text = f"unexpected:{type(ctx).__name__}"
        except AuthenticationFailed as exc:
            text = f"failed:{exc.detail}"
        except Exception as exc:  # noqa: BLE001 - Django would answer 500
            text = f"error:{type(exc).__name__}"
        out["headers"].append({"header": encoded, "result": text})
    transaction.set_rollback(True)
print("DJANGO_DECISIONS " + json.dumps(out, ensure_ascii=False))
