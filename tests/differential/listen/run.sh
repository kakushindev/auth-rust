#!/usr/bin/env bash
# Record Go 1.25.5's net.Listen("tcp", ..) for every case in main.go (the Go
# that builds 2026.2.7's front server), then replay the record through the
# Rust config parser and binder. Fails if the record changed or Rust differs.
set -euo pipefail
cd "$(dirname "$0")/../../.."
record=rust/packages/ak-axum/testdata/go_listen.json
docker run --rm -v "$PWD/tests/differential/listen:/src:ro" -w /src \
  golang:1.25.5-alpine go run main.go > "$record.new"
if ! diff -u "$record" "$record.new"; then
  echo "Go record changed; review and move $record.new over $record" >&2
  exit 1
fi
rm "$record.new"
scripts/rust-check.sh test -p authentik-axum -p authentik-common -- go_listen_matches_go
