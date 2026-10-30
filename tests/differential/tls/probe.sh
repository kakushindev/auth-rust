#!/usr/bin/env bash
# Print which TLS versions, TLS 1.2 cipher suites, TLS 1.3 suites and key
# exchange groups a server accepts, plus its certificate per SNI.
# Usage: probe.sh HOST:PORT [SNI...]   (needs openssl >= 3)
set -uo pipefail
target=$1; shift
try() { echo | openssl s_client -connect "$target" "$@" 2>/dev/null | grep -q "^New, TLSv1\.[23], Cipher is" && echo yes || echo no; }
for v in tls1 tls1_1 tls1_2 tls1_3; do echo "version $v $(try -$v)"; done
for c in $(openssl ciphers -s -tls1_2 'ALL:@SECLEVEL=0' | tr ':' ' '); do
  [ "$(try -tls1_2 -cipher "$c:@SECLEVEL=0")" = yes ] && echo "tls1.2 cipher $c"
done
for c in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
  [ "$(try -tls1_3 -ciphersuites "$c")" = yes ] && echo "tls1.3 suite $c"
done
for g in X25519 P-256 P-384 P-521 X448 X25519MLKEM768; do
  [ "$(try -tls1_3 -groups "$g")" = yes ] && echo "group $g"
done
for v in tls1_2 tls1_3; do
  # The pause lets post-handshake TLS 1.3 tickets arrive: Go sends its
  # ticket in the first flight, rustls one round trip later.
  out=$( (sleep 0.3; echo) | openssl s_client -connect "$target" -$v -servername tls-default.invalid 2>/dev/null)
  echo "default $v cipher $(sed -n 's/^New, TLSv1\.[23], Cipher is //p' <<<"$out")"
  echo "default $v $(sed -n 's/^Peer signature type: /sig /p;s/^Peer Temp Key: /key /p' <<<"$out" | tr '\n' ' ')"
  echo "default $v tickets $(grep -c 'TLS session ticket:' <<<"$out") hints $(sed -n 's/^ *TLS session ticket lifetime hint: //p' <<<"$out" | tr '\n' ' ')"
done
for sni in "" "$@"; do
  args=(-noservername); [ -n "$sni" ] && args=(-servername "$sni")
  subj=$(echo | openssl s_client -connect "$target" "${args[@]}" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null)
  echo "sni '${sni}' cert ${subj:-<handshake failed>}"
done
