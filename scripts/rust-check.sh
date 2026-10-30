#!/usr/bin/env bash
# Fast compile/lint loop for the `authentik` server package inside the exact
# candidate build environment (pyo3 against the reference image's Python,
# aws-lc FIPS toolchain). Caches live in named Docker volumes.
# Usage: scripts/rust-check.sh [cargo args...]   (default: clippy --features core)
set -euo pipefail
cd "$(dirname "$0")/.."
args=("$@")
if [[ ${#args[@]} -eq 0 ]]; then
  args=(clippy --package authentik --no-default-features --features core --all-targets)
fi
docker run --rm \
  -v "$PWD/rust:/build" \
  -v ak-rs-cargo-registry:/root/.cargo/registry \
  -v ak-rs-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -w /build \
  --entrypoint cargo \
  authentik-rs-toolchain:2026.2.7 "${args[@]}"
