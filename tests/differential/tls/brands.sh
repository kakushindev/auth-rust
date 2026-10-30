#!/usr/bin/env bash
# Brand TLS differential. Seeds identical keypairs and brands into the
# ref, ref2 and cand snapshot databases of a running HTTP differential
# (tests/differential/http/run.sh --keep), restarts the servers so both
# brand checkers load them right away, then compares per SNI: the
# certificate served, the client CA names requested, and whether a client
# certificate from an unrelated CA is accepted. Also compares the TLS
# surface (probe.sh). Needs openssl >= 3. Usage: brands.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."
here=tests/differential/tls
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
dc() { docker compose -p ak-diff -f tests/differential/http/compose.yml "$@"; }

gen() { # name subject [key-algorithm [openssl req options...]]
  openssl req -x509 -newkey "${3:-rsa:2048}" "${@:4}" -nodes -days 30 -subj "/CN=$2" \
    -keyout "$work/$1.key" -out "$work/$1.crt" 2>/dev/null
}
gen web-a tls-a.test
gen web-b tls-b.test ec -pkeyopt ec_paramgen_curve:P-256
gen nokey tls-nokey.test
gen nullfp tls-nullfp.test
gen client-ca "Brand Client CA"
gen stranger "Unrelated Client"

fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2 | tr 'A-F' 'a-f'; }
q() { python3 -c 'import sys; print("$q$" + open(sys.argv[1]).read() + "$q$")' "$1"; }
kp() { # uuid name cert key fingerprint
  local key="''" fpr="NULL"
  [ -n "$4" ] && key=$(q "$4")
  [ -n "$5" ] && fpr="'$5'"
  echo "INSERT INTO authentik_crypto_certificatekeypair (created, last_updated, kp_uuid, name, certificate_data, key_data, fingerprint_sha256)
        VALUES (now(), now(), '$1', '$2', $(q "$3"), $key, $fpr);"
}
brand() { # uuid domain web_certificate_id
  echo "INSERT INTO authentik_brands_brand (brand_uuid, domain, \"default\", branding_title, branding_logo,
          branding_favicon, attributes, branding_custom_css, branding_default_flow_background, web_certificate_id)
        SELECT '$1', '$2', false, branding_title, branding_logo, branding_favicon, attributes,
          branding_custom_css, branding_default_flow_background, $3
        FROM authentik_brands_brand WHERE \"default\" LIMIT 1;"
}
{
  echo "DELETE FROM authentik_brands_brand_client_certificates WHERE brand_id::text LIKE '22222222-%';
        DELETE FROM authentik_brands_brand WHERE brand_uuid::text LIKE '22222222-%';
        DELETE FROM authentik_crypto_certificatekeypair WHERE kp_uuid::text LIKE '11111111-%';"
  kp 11111111-0000-0000-0000-00000000000a web-a "$work/web-a.crt" "$work/web-a.key" "$(fp "$work/web-a.crt")"
  kp 11111111-0000-0000-0000-00000000000b web-b "$work/web-b.crt" "$work/web-b.key" "$(fp "$work/web-b.crt")"
  kp 11111111-0000-0000-0000-00000000000c nokey "$work/nokey.crt" "" "$(fp "$work/nokey.crt")"
  kp 11111111-0000-0000-0000-00000000000d nullfp "$work/nullfp.crt" "$work/nullfp.key" ""
  kp 11111111-0000-0000-0000-00000000000e client-ca "$work/client-ca.crt" "" "$(fp "$work/client-ca.crt")"
  brand 22222222-0000-0000-0000-00000000000a tls-a.test "'11111111-0000-0000-0000-00000000000a'"
  brand 22222222-0000-0000-0000-00000000000b tls-b.test "'11111111-0000-0000-0000-00000000000b'"
  brand 22222222-0000-0000-0000-00000000000c tls-nokey.test "'11111111-0000-0000-0000-00000000000c'"
  brand 22222222-0000-0000-0000-00000000000d tls-nullfp.test "'11111111-0000-0000-0000-00000000000d'"
  brand 22222222-0000-0000-0000-00000000000e tls-client.test NULL
  echo "INSERT INTO authentik_brands_brand_client_certificates (brand_id, certificatekeypair_id)
        VALUES ('22222222-0000-0000-0000-00000000000e', '11111111-0000-0000-0000-00000000000e');"
} > "$work/seed.sql"
for db in ref-db ref2-db cand-db; do
  dc exec -T "$db" psql -q -v ON_ERROR_STOP=1 -U authentik -d authentik < "$work/seed.sql"
done

docker restart ak-diff-ref-1 ak-diff-ref2-1 ak-diff-cand-1 >/dev/null
for port in 29000 29200 29100; do
  for _ in $(seq 1 120); do
    curl -fsS -o /dev/null "http://127.0.0.1:$port/-/health/ready/" && break
    sleep 2
  done
done
sleep 15 # both checkers run as soon as the backend is up

snis=("" authentik.test tls-a.test x.tls-a.test nottls-a.test tls-b.test tls-nokey.test
      tls-nullfp.test tls-client.test sub.tls-client.test other.test)
probe() { # port
  "$here/probe.sh" "127.0.0.1:$1"
  for sni in "${snis[@]}"; do
    args=(-noservername); [ -n "$sni" ] && args=(-servername "$sni")
    out=$(echo | openssl s_client -connect "127.0.0.1:$1" "${args[@]}" 2>/dev/null || true)
    subj=$(openssl x509 -noout -subject 2>/dev/null <<<"$out" || true)
    cas=$(awk '/^Acceptable client certificate CA names/{f=1;next} /^(Client Certificate Types|Requested Signature Algorithms|Shared Requested)/{f=0} f' <<<"$out" | tr '\n' ';')
    sigalgs=$(sed -n 's/^Requested Signature Algorithms: //p' <<<"$out")
    with_client=$(echo | openssl s_client -connect "127.0.0.1:$1" "${args[@]}" \
      -cert "$work/stranger.crt" -key "$work/stranger.key" 2>/dev/null \
      | grep -q '^New, TLSv1\.[23], Cipher is' && echo accepted || echo refused)
    echo "sni '$sni': ${subj:-<handshake failed>} | client CAs: ${cas:-none} ${sigalgs:+| requested $sigalgs }| unrelated client cert: $with_client"
  done
}
probe 29443 > "$work/ref.txt"
probe 29643 > "$work/ref2.txt"
probe 29543 > "$work/cand.txt"
cat "$work/ref.txt"
status=0
diff -u "$work/ref.txt" "$work/ref2.txt" > /dev/null || { echo "NOISE: ref and ref2 differ"; diff -u "$work/ref.txt" "$work/ref2.txt"; status=1; }
if diff -u "$work/ref.txt" "$work/cand.txt"; then echo "TLS differential: reference and candidate identical"; else status=1; fi
exit $status
