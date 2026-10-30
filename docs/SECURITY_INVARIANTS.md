# Security invariants

An invariant is **verified** only when a test that ran against the pinned reference shows equal behavior. Otherwise it is a requirement still to be verified.

## Verified

### Password hashing (`rust/crates/ak-passwords`)

Evidence: `tests/differential/passwords/run.sh` (2026-10-30) against `ghcr.io/goauthentik/server:2026.8.5`.

1. **Same hashers, same order.** `PASSWORD_HASHERS` is Django's default list (checked in the running reference): `pbkdf2_sha256` (preferred), `pbkdf2_sha1`, `argon2`, `bcrypt_sha256`, `scrypt`.
2. **Byte-identical encodings.** For 152 (password, salt, parameters) cases, including empty, non-ASCII, emoji, `$`-containing, NUL-containing and 100-byte passwords, Rust output equals Django output.
3. **Parameters match the installed Django, not the docs.** PBKDF2 1 000 000 iterations; argon2id t=2, m=102400, p=8, 32-byte hash; bcrypt 12 rounds over a hex SHA-256 pre-hash; scrypt N=16384, r=8, **p=5**, 64-byte key. The differential run caught that p is 5, not 1.
4. **`verify_password` outcomes.** 65 cases agree on `(is_correct, must_update)`, or on raising. This covers correct and wrong passwords, outdated iteration counts, low-entropy salts (`must_update` true), unusable `!…` hashes, legacy unsalted MD5/SHA1 forms (rejected because those hashers are not installed), unknown algorithms, and malformed hashes for every hasher.
5. **Failure modes are preserved, not silently converted.** Where Django raises (`ValueError`, `InvalidHashError`, `TypeError` for a `None` hash), Rust returns `Err(HashError)`. Where Django returns False (argon2 decode failures, too-short salts, argon2-cffi verification errors), Rust returns `Ok(false)`.
6. **Timing equalization.** For unusable hashes, a `None` password or an unknown hasher, a full default PBKDF2 hash runs (Django #20760 `fake_runtime`). `harden_runtime` runs the missing PBKDF2 iterations, or the extra bcrypt rounds, when a wrong password meets an outdated hash.
7. **Constant-time comparison** of the encoded strings (`subtle`, matching `hmac.compare_digest`).
8. **Rehash rule.** Callers rehash only when `is_correct && must_update`. That is `check_password`'s setter condition, which `User.check_password` uses to save without sending the `password_changed` signal.
9. **Interoperability both ways.** Django `check_password` accepts all 31 Rust-generated hashes (all five hashers plus an unusable password) and rejects wrong passwords. The real `akadmin` row in the reference database verifies in Rust.
10. **Salts.** 22 characters from `[a-zA-Z0-9]` via a CSPRNG (128-bit entropy, `get_random_string`). bcrypt salts come from `gensalt(12)` semantics.

## Required, not yet verified (each needs a differential test before its feature can be marked complete)

- Session cookie name, attributes (`HttpOnly`, `Secure`, `SameSite`, domain/path from brand/config), signing with `SECRET_KEY`, DB session lifecycle, `AuthenticatedSession` binding, and the session-binding middleware (`BoundSessionMiddleware`: GeoIP/network binding).
- CSRF (`authentik.root.middleware.CsrfViewMiddleware`): token format, trusted origins, exemptions for token auth.
- API token auth (`TokenBackend`, `Authorization: Bearer`), token intents and expiry, and the outpost service account tokens.
- Permission checks: django-guardian object permissions plus RBAC roles; `InitialPermissionsMiddleware`.
- Impersonation (`ImpersonateMiddleware`) rules and audit events.
- Flow executor security: the flow plan stored in the session, stage ordering, policy re-evaluation, `pending_user` handling, and redirect sanitization.
- Reputation and rate limiting (`policies/reputation`), and lockout semantics.
- OAuth2/OIDC: redirect URI matching modes (strict/regex), PKCE (S256/plain), code reuse revocation, refresh token rotation, `nonce`/`state`, ID token claims and signing keys, JWKS, client authentication methods.
- SAML: signature and digest algorithms, assertion validity windows, audience/recipient checks, replay protection, encryption.
- MFA: TOTP window and drift, static token single use, WebAuthn challenge/origin/RP ID/counter, device classes.
- Key and certificate handling (`authentik/crypto`): `CertificateKeyPair` storage format, discovery from the filesystem.
- Tenant isolation (`django-tenants` `search_path`), brand resolution by host.
- Event/audit semantics: which actions emit which `Event` actions, with which context and client IP.
- Expression policies (Python expressions evaluated in a sandbox). A Rust runtime cannot run them natively; see `MIGRATION_PLAN.md` risk R1.
