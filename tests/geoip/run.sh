#!/usr/bin/env bash
# MaxMind lookups: copy the GeoLite2 databases out of the reference image,
# record CPython's maxminddb/geoip2 answers for 4328 addresses with the
# image's Python, and check that ak-geoip answers the same.
set -euo pipefail
cd "$(dirname "$0")/../.."
image=ghcr.io/goauthentik/server:2026.2.7
export AK_GEOIP_DIR="$(mktemp -d)"
trap 'rm -rf "$AK_GEOIP_DIR"' EXIT
cid="$(docker create "$image")"
docker cp "$cid:/geoip/GeoLite2-ASN.mmdb" "$AK_GEOIP_DIR/" >/dev/null
docker cp "$cid:/geoip/GeoLite2-City.mmdb" "$AK_GEOIP_DIR/" >/dev/null
docker rm "$cid" >/dev/null
docker run --rm -i --entrypoint python "$image" -I - < tests/geoip/gen_vectors.py > "$AK_GEOIP_DIR/vectors.json"
cd rust && cargo test --release -p ak-geoip -- --nocapture
