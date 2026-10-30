# Protocol compatibility

Each protocol is ported only behind the strangler router (`ARCHITECTURE.md`) and enabled once its interoperability suite passes against both implementations.

| Protocol | Upstream implementation | Upstream interoperability tests | Rust status |
| --- | --- | --- | --- |
| OAuth 2.0 / OIDC provider | `authentik/providers/oauth2` (6 481 lines): authorize, token (code, refresh, client credentials, device, JWT bearer/federation), PKCE, introspection, revocation, userinfo, end-session, discovery, JWKS, back/front-channel logout | `tests/openid_conformance/*` (OIDF suite: basic, implicit, config, rp-initiated, front/back-channel), `tests/e2e/test_provider_oidc*.py`, `test_provider_oauth2_*` | Not started |
| SAML 2.0 provider | `authentik/providers/saml` (3 912 lines): SSO (redirect/POST/artifact-less), SLO, metadata, signing/encryption | `tests/e2e/test_provider_saml.py` (test-saml-idp) | Not started |
| WS-Federation (EE) | `authentik/enterprise/providers/ws_federation` | `tests/e2e/test_provider_ws_fed.py` | Blocked (EE license) |
| LDAP provider | Go outpost `internal/outpost/ldap` + `authentik/providers/ldap` | `tests/e2e/test_provider_ldap.py` | Not started |
| RADIUS provider | Go outpost `internal/outpost/radius` + `authentik/providers/radius` | `tests/e2e/test_provider_radius.py` | Not started |
| RAC (RDP/SSH/VNC via guacd) | Go outpost `internal/outpost/rac` + `authentik/providers/rac` | `tests/e2e/test_provider_rac.py` | Not started |
| Proxy / forward auth | Rust `src/outpost/proxy` (already Rust upstream) + `authentik/providers/proxy` | `tests/e2e/test_provider_proxy*.py`, `proxy_forward_auth/` | Rust upstream; reuse, not yet re-verified here |
| SCIM provider | `authentik/providers/scim`, `lib/sync` | provider tests in `authentik/providers/scim/tests` | Not started |
| SCIM source | `authentik/sources/scim` | `tests/e2e/test_source_scim.py` | Not started |
| OAuth 1/2 sources | `authentik/sources/oauth` (2 857 lines, many vendor types) | `tests/e2e/test_source_oauth_*.py` | Not started |
| SAML source | `authentik/sources/saml` | `tests/e2e/test_source_saml.py` | Not started |
| LDAP source (sync + password backend) | `authentik/sources/ldap` | `tests/e2e/test_source_ldap_samba.py` | Not started |
| Kerberos source | `authentik/sources/kerberos` (needs MIT krb5) | `authentik/sources/kerberos/tests` | Not started |
| Plex, Telegram sources | `authentik/sources/plex`, `telegram` | unit tests | Not started |
| WebAuthn / passkeys | `authentik/stages/authenticator_webauthn`, `authenticator_validate` | `tests/e2e/test_flows_authenticators_webauthn.py` | Not started |
| TOTP / static / email / SMS / Duo | `authentik/stages/authenticator_*` | `tests/e2e/test_flows_authenticators.py` | Not started |
| SSF transmitter (EE) | `authentik/enterprise/providers/ssf` | `tests/openid_conformance/test_ssf_transmitter.py` | Blocked (EE license) |
| Outpost control channel | WebSocket `ws/outpost/…` (channels over Postgres), outpost API | Go outpost unit tests | Not started |

Library selection is decided per protocol at implementation time and must pass the corresponding upstream interop suite. No custom cryptographic primitives.
