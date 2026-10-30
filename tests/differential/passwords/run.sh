#!/usr/bin/env bash
# Password hasher differential test against the running reference stack.
#  1. Django -> Rust: regenerate the fixture consumed by `cargo test -p ak-passwords`.
#  2. Rust -> Django: Rust-made hashes must pass Django's check_password.
#  3. Real row: the bootstrap user's stored hash must verify in Rust.
set -euo pipefail
cd "$(dirname "$0")/../../.."
export PATH="$HOME/.cargo/bin:$PATH"
dc() { docker compose -f reference/compose.yml --env-file reference/.env "$@"; }
fixture=rust/crates/ak-passwords/tests/fixtures/django_hashers.json

dc exec -T server ak shell -c "$(cat tests/differential/passwords/django_fixture.py)" 2>/dev/null \
  | sed -n 's/^@@FIXTURE@@//p' > "$fixture.tmp"
mv "$fixture.tmp" "$fixture"
(cd rust && cargo test -q -p ak-passwords)

hashes=$(cd rust && cargo run -q -p ak-passwords --example emit_hashes)
result=$(dc exec -T -e AUTHENTIK_RUST_HASHES="$hashes" server ak shell \
  -c "$(cat tests/differential/passwords/check_rust_hashes.py)" 2>/dev/null | sed -n 's/^@@CHECK@@ //p')
echo "$result" | tail -1
echo "$result" | grep -q 'failures=0'

stored=$(dc exec -T postgresql psql -U authentik -d authentik -Atc \
  "select password from authentik_core_user where username = 'akadmin'")
bootstrap=$(sed -n 's/^AUTHENTIK_BOOTSTRAP_PASSWORD=//p' reference/.env)
(cd rust && AK_STORED_HASH="$stored" AK_PASSWORD="$bootstrap" \
  cargo run -q -p ak-passwords --example verify_stored)
