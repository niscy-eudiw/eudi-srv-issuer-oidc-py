# Changelog

## [0.9.5]

_5 Aug 2026_

### Changed
- Updated implementation to align with EUDI TS3 v1.5 specification.

## [0.9.6]

_06 Oct 2026_

### Added
- `session_token` in the redirect to the issuer backend: an ES256 JWT with the session id, scope and authorization details, so the backend no longer trusts query parameters.
- `backend_api_key` configuration: `/preauth_generate` and `/introspection` require it in the `X-Api-Key` header; anyone could mint pre-authorized codes.
- DPoP binding: proofs at `/token` are checked (signature, `htm`, `htu`, `iat`, single-use `jti`), the access token is bound to the proof key, and `/introspection` returns `cnf.jkt`.
- Per-client rate limits (`rate_limiting`, Flask-Limiter) on `/token`, `/pushed_authorization`, `/authorization` and `/verify/user` (not on the backend-only `/preauth_generate` and `/introspection`, where one address serves every user).
- Test suite (`tests/`) and a CI workflow running it.

### Changed
- A wallet-supplied `issuer_state` is no longer used as the session id, which let a client choose or overwrite a session.
- `/verify/user` only completes the session created for the authorization request in its token.
- Pre-authorized codes expire after 10 minutes, can be redeemed once, and are revoked after 5 wrong `tx_code` attempts; the `tx_code` is generated with `secrets`.
- Keys are no longer committed: they are generated on first start into `private/` (mount a volume to keep them). `httpc_params.verify` is now `true` and `debug` is off.
- HMAC algorithms removed from `dpop_signing_alg_values_supported`.
- The discovery document no longer advertises logout support that is not implemented, and lists the pre-authorized code grant.
- Session cookies are `Secure` and `HttpOnly`.
- Requirements use the niscy-eudiw idpy-oidc fork pinned to a commit.
- The Docker image runs as an unprivileged user (UID 10001) and only copies the application files.
- CI: SonarCloud runs on `pull_request` instead of `pull_request_target` and actions are pinned to commit SHAs.
- Removed the `/jwt_token` test route.
- A Wallet Instance Attestation is required at `/pushed_authorization` and `/token`: `client_authn_method` is only `wallet_attestation`. The `public` method let any client skip the WIA (trust, revocation and proof-of-possession checks) by not sending it.
- The internal pre-authorized code call skips the WIA `sub` / `client_id` comparison through a server-side flag; the fork no longer skips it for any request with `redirect_uri=preauth`.

### Fixed
- Unknown authorization or pre-authorized codes and non-numeric `tx_code` values returned 500 instead of 400.
- Codes, tokens, tx_codes and DPoP / authorization headers are redacted from logs, and `request_manager` logs through `logging` instead of `print`.
- `check_session_iframe` compared the client id with the whole client database.
- A pushed authorization request whose client authentication (e.g. the WIA) fails returns that error instead of a 500.
- Client authentication failures at `/token` and `/pushed_authorization` return 401 `invalid_client` instead of 400.
