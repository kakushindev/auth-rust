# Appended after `COOKIES = …` by run.sh; run with `python -m manage shell`.
"""Bind the bound-* sessions as the user_login stage would (network/GeoIP
binding and last IP; two also get an expiry), saved through SessionStore."""

from datetime import timedelta

from django.utils import timezone

from authentik.core.sessions import SessionStore
from authentik.stages.user_login.middleware import SESSION_KEY_BINDING_GEO, SESSION_KEY_BINDING_NET

BINDINGS = {
    "bound-asn": ("8.8.8.8", "bind_asn", None, None),
    "bound-asn-network-ip": ("8.8.8.8", "bind_asn_network_ip", None, None),
    "bound-city": ("81.2.69.142", None, "bind_continent_country_city", None),
    "bound-continent": ("81.2.69.142", "no_binding", "bind_continent", None),
    "bound-no-binding": ("8.8.8.8", "no_binding", "no_binding", None),
    "bound-expiry-seconds": ("8.8.8.8", "bind_asn", None, 7200.0),
    "bound-expiry-date": ("8.8.8.8", "bind_asn", None, timedelta(hours=3, seconds=0.5)),
    "bound-impersonating": ("8.8.8.8", "bind_asn", None, None),
}
done = 0
for case in COOKIES:  # noqa: F821
    name = case["name"].removeprefix("real:")
    if name not in BINDINGS or "client_ip" in case:
        continue
    last_ip, net, geo, expiry = BINDINGS[name]
    store = SessionStore(session_key=case["sid"])
    store._session_cache = store.load()
    store["last_ip"] = last_ip
    if net is not None:
        store[SESSION_KEY_BINDING_NET] = net
    if geo is not None:
        store[SESSION_KEY_BINDING_GEO] = geo
    if expiry is not None:
        store.set_expiry(timezone.now() + expiry if isinstance(expiry, timedelta) else expiry)
    store.save()
    done += 1
print(f"[bind] {done}")
