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

## [Unreleased]

### Fixed
- tx_code attempt limit under concurrency: a burst of wrong guesses all found the pre-authorized code before any revoked it, so more than 5 were compared (9 of 20 in a local test). `RequestManager.check_tx_code` compares and counts in one locked step and never compares a code that reached the limit; it replaces `register_tx_code_failure`.
- PAR relayed by the issuer frontend shared one rate limit: the frontend names the wallet in `X-Forwarded-For`, but the server only trusted that header behind `trusted_proxies`, where any client could set it. New `rate_limiting.forwarders`: peers whose requests are limited per forwarded wallet address; no other client can choose its key. Default empty (unchanged behaviour); set it to the frontend's address.
- Concurrent requests registering the same client (the internal pre-authorized client on every credential offer, or a wallet running two flows at once) could see the client entry half-written and fail with "No registered redirect_uri" (500 at `/preauth`), or lose a redirect URI. `dynamic_registration` now runs under a lock, leaves a client untouched when its redirect URI is already registered, adds a new URI to a copy that replaces the entry in one step, and its `restore` takes back only the URI it added (`TestConcurrentRegistration`).
- Concurrent token requests with one authorization or pre-authorized code could each get tokens. Fixed in the idpy-oidc fork (one redemption per code at a time); the pin moves to it below.

### Changed
- The idpy-oidc fork pin moves to `6d99cc4`, which adds the code redemption lock.
- The idpy-oidc fork pin moves to `b7da7c6`, the commit with the wallet attestation fixes (WIA signature always checked, PoP `aud` / `iss` / single-use `jti`, `sub` = `client_id`). The previous pin `3f3a5bd` predates them, so an image built from `requirements.txt` ran without them.
- `pyjwt` 2.12.1 → 2.15.1 (PYSEC-2026-178, PYSEC-2026-4140 to 4152, PYSEC-2026-4183).
- The listen address is configurable as `webserver.host` (default `0.0.0.0`, which containers need); it was hard-coded.
- PKCE is required by default, with `S256` only, at `/pushed_authorization` and `/authorization`: the add-on option was misspelt (`code_challenge_method`), so PKCE was optional and `plain` was accepted. `add_ons.pkce.kwargs.essential: false` makes it optional again (OpenID4VCI only recommends it); a challenge that is sent must still use an accepted method. The server's own pre-authorized code request skips it.
- Authorization requests must be pushed by default (`require_pushed_authorization_requests: true`; OpenID4VCI recommends PAR, HAIP requires it): the plain `/authorization` request registered any `client_id` and `redirect_uri` before any client authentication. Set it to `false` to test wallets without PAR.
- Redirect URIs must be `https`, `http` on a loopback address, or a reverse-domain private-use scheme (RFC 8252), without a fragment; `preauth` is reserved for the server's own pre-authorized code request. A pushed request whose client authentication fails leaves the client entry as it was.
- `/token` requires a DPoP proof by default (`require_dpop: true`); tokens were issued as bearer tokens without one. `false` allows bearer tokens again.
- `require_wallet_attestation` (default `true`): `false` lets wallets authenticate as public clients at PAR and `/token`; a wallet attestation that is sent is still verified.
- `/.well-known/openid-configuration` reports the values in force: `require_pushed_authorization_requests`, `code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`.
- The configuration example is now `config.yaml`, with a comment on every setting (`config.json` is removed; JSON files with the same keys still load). The Docker image reads `/etc/issuer_config/authorization_config.yaml`: rename the mounted file, or point the command at your `.json` file.
- The token handed through `/verify/user` expires (`token_lifetime`, default 30 minutes), is accepted only from this server (`iss`, signing algorithm) and only once.
- The access token's `client_status` comes from the wallet attestation verified in that request, not from the shared client entry.
- Removed `/registration`, `/registration_api` (open client registration that fetched remote `jwks_uri` / `sector_identifier_uri`), `/userinfo`, `/session`, `/check_session_iframe`, `/verify_logout`, `/rp_logout` and `/post_logout` with their endpoints and templates; the discovery document no longer lists them and states `require_pushed_authorization_requests`.

### Fixed
- Authorization errors redirected to any `redirect_uri` the request named (open redirect): they go only to a URI registered for the client, otherwise as JSON.
- A lock-order inversion in `request_manager` could deadlock a lookup of an expired request against the clean-up. Expired requests are now also cleaned up when requests are added (not only on `/authorization`), and the store is capped (`RequestLimitExceeded`).
- `/keys/<file>` answered 500 for a missing file; it serves only `.json` files.
- The unsupported grant type branch logged the token request form unredacted.
