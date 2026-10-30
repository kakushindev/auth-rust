#!/usr/bin/env bash
# 502 differential: with the stacks of run.sh --keep up, make the gunicorn
# socket unreachable in ref and cand the same way (missing, then a regular
# file in its place), compare the 502 responses (JSON and text), and restore
# the socket. Usage: backend_down.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."
port() { case $1 in ak-diff-ref-1) echo 29000 ;; ak-diff-cand-1) echo 29100 ;; esac; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

on() { docker exec -u root "$1" sh -c "$2"; }
fetch() { # container accept
  curl -s -o "$work/body" -w '%{http_code} %{content_type}' -H 'Host: authentik.test' \
    -H "Accept: $2" "http://127.0.0.1:$(port "$1")/api/v3/root/config/"
  printf ' %s\n' "$(cat "$work/body")"
}
for c in ak-diff-ref-1 ak-diff-cand-1; do
  sock=$(on "$c" 'echo ${TMPDIR:-/tmp}/authentik-core.sock' | sed 's#//#/#')
  on "$c" "mv $sock $sock.bak"
  sleep 3 # pooled connections close on gunicorn's 2 s keep-alive
  { echo "missing socket:"; fetch "$c" application/json; fetch "$c" text/plain
    on "$c" "touch $sock"
    echo "regular file:"; fetch "$c" application/json; fetch "$c" text/plain
  } > "$work/$c.txt"
  on "$c" "rm -f $sock && mv $sock.bak $sock"
done
cat "$work/ak-diff-ref-1.txt"
if diff -u "$work/ak-diff-ref-1.txt" "$work/ak-diff-cand-1.txt"; then
  echo "502 differential: identical"
else
  exit 1
fi
