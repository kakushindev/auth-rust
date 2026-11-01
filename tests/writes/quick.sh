#!/usr/bin/env bash
# Fast loop for write endpoints: build a debug binary incrementally in the
# toolchain container, run the candidate image with it mounted, and replay
# only the given write groups (write_diff.py --only). Reads, session and
# logout checks are skipped; the schema guard still runs. Before a commit,
# run the full suite: CANDIDATE_IMAGE=... tests/api/run.sh
# Usage: tests/writes/quick.sh group[,group...] [--keep]
set -euo pipefail
cd "$(dirname "$0")/../.."
groups="${1:?usage: quick.sh group[,group...] [--keep]}"
shift
toolchain=authentik-rs-toolchain:2026.2.7
mkdir -p rust/.cand
if ! out="$(docker run --rm -v "$PWD/rust:/build" -v ak-rs-cargo-registry:/root/.cargo/registry \
  -v ak-rs-target:/target -e CARGO_TARGET_DIR=/target -w /build --entrypoint cargo "$toolchain" \
  build --package authentik --no-default-features --features core --locked 2>&1)"; then
  grep -E '^error' -A12 <<<"$out" | head -60
  exit 1
fi
# A new file renamed into place: a kept candidate still runs the old one.
docker run --rm -v ak-rs-target:/target -v "$PWD/rust/.cand:/out" --entrypoint sh "$toolchain" \
  -c 'cp /target/debug/authentik /out/authentik.new && mv -f /out/authentik.new /out/authentik'
CAND_BINARY="$PWD/rust/.cand/authentik" CANDIDATE_IMAGE="${CANDIDATE_IMAGE:-authentik-rs-candidate:2026.2.7}" \
  API_SUITES=writes WRITE_ONLY="$groups" tests/api/run.sh "$@"
