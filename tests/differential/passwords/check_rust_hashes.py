# Runs inside the reference container: reads JSON lines of Rust-generated
# hashes from AUTHENTIK_RUST_HASHES and checks them with Django's own hashers.
import json
import os

from django.contrib.auth.hashers import check_password, identify_hasher, is_password_usable

failures = 0
lines = [json.loads(line) for line in os.environ["AUTHENTIK_RUST_HASHES"].splitlines() if line]
for case in lines:
    password, encoded = case["password"], case["encoded"]
    if not is_password_usable(encoded):
        ok = not check_password(password, encoded)
        algo = "unusable"
    else:
        algo = identify_hasher(encoded).algorithm
        ok = check_password(password, encoded) and not check_password(password + "x", encoded)
    if not ok:
        failures += 1
    print(f"@@CHECK@@ {'PASS' if ok else 'FAIL'} {algo} {password!r}")
print(f"@@CHECK@@ total={len(lines)} failures={failures}")
