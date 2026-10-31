"""MaxMind lookups as 2026.2.7 makes them, as JSON on stdout.

Run with the image's Python against the image's databases:
    docker run --rm -i --entrypoint python ghcr.io/goauthentik/server:2026.2.7 -I - < gen_vectors.py

For each address: maxminddb's raw record and prefix length for both
databases, and what geoip2 makes of them (ASN number and network; the
continent, country and city records' to_dict()), or the exception raised.
"""

import ipaddress
import json
import random
import sys

import geoip2.database
import maxminddb

ASN = "/geoip/GeoLite2-ASN.mmdb"
CITY = "/geoip/GeoLite2-City.mmdb"

rng = random.Random(20261031)
ips = [
    "8.8.8.8", "1.1.1.1", "81.2.69.142", "203.0.113.9", "198.51.100.7", "10.0.0.1", "127.0.0.1",
    "0.0.0.0", "255.255.255.255", "100.64.0.1", "169.254.1.1", "224.0.0.1", "36.86.63.180",
    "103.10.20.30", "::", "::1", "::ffff:8.8.8.8", "::8.8.8.8", "2002:808:808::1", "2001:0:4136:e378::1",
    "2001:4860:4860::8888", "2606:4700:4700::1111", "fe80::1", "fc00::1", "2400:cb00::1", "ff02::1",
    "2001:db8::1", "64:ff9b::808:808",
]
for _ in range(3000):
    ips.append(str(ipaddress.IPv4Address(rng.getrandbits(32))))
for _ in range(500):
    ips.append(str(ipaddress.IPv6Address((0x2000 + rng.getrandbits(13)) << 112 | rng.getrandbits(112))))
for _ in range(200):
    ips.append(str(ipaddress.IPv6Address(rng.getrandbits(128))))
for v4 in ips[28:328]:
    ips.append(f"::ffff:{v4}")
    ips.append(str(ipaddress.IPv6Address(0x2002 << 112 | int(ipaddress.IPv4Address(v4)) << 80)))

raw = {"asn": maxminddb.open_database(ASN), "city": maxminddb.open_database(CITY)}
models = {"asn": geoip2.database.Reader(ASN), "city": geoip2.database.Reader(CITY)}


def attempt(fn):
    try:
        return {"ok": fn()}
    except Exception as exc:  # noqa: BLE001
        return {"error": type(exc).__name__}


def asn_model(ip):
    a = models["asn"].asn(ip)
    return {"number": a.autonomous_system_number, "org": a.autonomous_system_organization, "network": str(a.network)}


def city_model(ip):
    c = models["city"].city(ip)
    return {"continent": c.continent.to_dict(), "country": c.country.to_dict(), "city": c.city.to_dict()}


out = []
for ip in ips:
    out.append({
        "ip": ip,
        "raw_asn": attempt(lambda: list(raw["asn"].get_with_prefix_len(ip))),
        "raw_city": attempt(lambda: list(raw["city"].get_with_prefix_len(ip))),
        "asn": attempt(lambda: asn_model(ip)),
        "city": attempt(lambda: city_model(ip)),
        # Wrong database type: geoip2 raises TypeError.
        "asn_on_city": attempt(lambda: models["city"].asn(ip) and None),
    })
meta = {k: {"type": r.metadata().database_type, "build": r.metadata().build_epoch} for k, r in raw.items()}
json.dump({"metadata": meta, "vectors": out}, sys.stdout, ensure_ascii=False)
print(len(out), "addresses", file=sys.stderr)
