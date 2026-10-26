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

Needs the idpy-oidc fork's `branch-refractoring` (installed from `requirements.txt`).

### Added
- `cleanup_interval` (minutes, default 60): a background thread (`housekeeping.py`) removes expired authorization requests, redeemed authentication tokens and pushed authorization requests that were never redeemed. Lookups already refused expired entries, but entries nobody looked up again stayed in memory; `/authorization` no longer cleans on every request.
- `require_wallet_attestation` (default `true`): `false` lets wallets authenticate as public clients at PAR and `/token`; a wallet attestation that is sent is still verified.
- `par_allowed_htu` (DPoP add-on): the public `/pushed_authorization` URLs a DPoP proof sent there may name.
- `pop_allowed_aud` (token endpoint `kwargs`): the issuer identifiers of the frontends that relay PAR and `/token`, accepted as the wallet attestation PoP `aud`.
- `status_validation_context` (token endpoint `kwargs`, default `WalletOrKeyStorageStatus`): the status validator context for the WIA `client_status` (was `PIDStatus`).
- `rate_limiting.forwarders`: peers whose requests are limited per forwarded wallet address (`X-Forwarded-For`). The issuer frontend relays PAR, so every wallet shared one limit; `trusted_proxies` could not be used since there any client could set the header. Default empty (unchanged behaviour); set it to the frontend's address.
- The listen address is configurable as `webserver.host` (default `0.0.0.0`, which containers need); it was hard-coded.

### Changed
- Secure defaults for the options OpenID4VCI only recommends; each can be switched off to test wallets without the feature:
  - PKCE is required, with `S256` only, at `/pushed_authorization` and `/authorization`: the add-on option was misspelt (`code_challenge_method`), so PKCE was optional and `plain` was accepted. `add_ons.pkce.kwargs.essential: false` makes it optional again; a challenge that is sent must still use an accepted method. The server's own pre-authorized code request skips it.
  - Authorization requests must be pushed (`require_pushed_authorization_requests: true`; HAIP requires it): the plain `/authorization` request registered any `client_id` and `redirect_uri` before any client authentication.
  - `/token` requires a DPoP proof (`require_dpop: true`); tokens were issued as bearer tokens without one.
  - `/.well-known/openid-configuration` reports the values in force: `require_pushed_authorization_requests`, `code_challenge_methods_supported`, `token_endpoint_auth_methods_supported`.
- DPoP is validated and bound by the idpy-oidc fork's DPoP add-on only: `dpop.py` (a second validator, the access token -> key map and the `cnf.jkt` added at `/introspection`) is removed. The fork checks the signature with a public asymmetric key and an allowed `alg`, `typ`, `htm`, `htu` against the configured `allowed_htu`, `iat` (5 minutes old, 60 s ahead) and a single-use `jti`; it binds the grant and its tokens to the key, refuses a refresh with another key or without a proof, and returns `cnf.jkt` from `/introspection`. Errors stay `400 invalid_dpop_proof`. `/token` returns the token endpoint's error responses as they are (JSON).
- `/authorization` passes only `client_id` and `request_uri` to the authorization endpoint, which resolves the pushed request itself (RFC 9126 section 4).
- Redirect URIs must be `https`, `http` on a loopback address, or a private-use scheme (RFC 8252 only recommends the reverse-domain form, so `asitplus-wallet://` is accepted) other than `javascript`, `data`, `vbscript`, `file`, `blob` and `about`, without a fragment; `preauth` is reserved for the server's own pre-authorized code request. A pushed request whose client authentication fails leaves the client entry as it was.
- OAuth error responses follow RFC 6749, RFC 9126 and RFC 9396 (`tests/test_error_conformance.py`, `test_error_conformance_authz.py`): errors are JSON with `error_description` (was `description`); `/pushed_authorization` answers `201 Created`, refuses a pushed `request_uri`, and refuses `authorization_details` that are not a non-empty array of `openid_credential` objects (`invalid_authorization_details`); an unknown or expired `request_uri` at `/authorization` is `400 invalid_request_uri` (was 404) and its `client_id` must match the pushed request's; errors before the pushed request is found are never redirected; a missing `grant_type` is `invalid_request`; token responses carry `Cache-Control: no-store`; POST-only endpoints answer other methods with `405` and `Allow: POST` (was 404); an unknown `/.well-known/` path is 404 (was 400); internal errors are `server_error`.
- Wallet attestation failures at `/token` and `/pushed_authorization` answer `400 invalid_client`: RFC 6749 section 5.2 requires 401 (with a `WWW-Authenticate` header) only when the client authenticates with the `Authorization` header, which a wallet attestation does not use.
- Refresh tokens and the issuance usage rules last one week (`expires_in` / `lifetime` 604800 s; wallets re-issue credentials with them), and the session behind a refresh token is kept at least as long, so the token can still be looked up.
- `server.create_app(config_file)` builds the application; `main()` and the tests use it (the tests copied the build steps before, so start-up was untested). Test coverage 70% -> 98%: `tests/test_server.py`, `test_views.py`, `test_security_helpers.py`, `test_housekeeping.py` and more `test_request_manager.py`.
- Dependencies are installed from `requirements.txt` like the other services; the idpy-oidc fork follows `branch-refractoring` instead of a pinned commit (an image built from an older pin ran without the wallet attestation fixes).
- `pyjwt` 2.12.1 -> 2.15.1 (PYSEC-2026-178, PYSEC-2026-4140 to 4152, PYSEC-2026-4183).
- The Docker build no longer upgrades pip (unpinned); the CI installs semgrep from wheels only (`--only-binary :all:`), so no setup script runs (SonarCloud).

### Fixed
- A code from an authorization request with `dpop_jkt` could be redeemed with a DPoP proof by any key (RFC 9449 section 10). It is now refused with `invalid_dpop_proof` unless the proof is by that key; a DPoP proof sent with the pushed authorization request binds the code the same way (section 10.1).
- Concurrent token requests with one authorization or pre-authorized code could each get tokens; the idpy-oidc fork now redeems a code once.
- tx_code attempt limit under concurrency: a burst of wrong guesses all found the pre-authorized code before any revoked it, so more than 5 were compared (9 of 20 in a local test). `RequestManager.check_tx_code` compares and counts in one locked step and never compares a code that reached the limit; it replaces `register_tx_code_failure`.
- Concurrent requests registering the same client (the internal pre-authorized client on every credential offer, or a wallet running two flows at once) could see the client entry half-written and fail with "No registered redirect_uri" (500 at `/preauth`), or lose a redirect URI. `dynamic_registration` now runs under a lock, leaves a client untouched when its redirect URI is already registered, adds a new URI to a copy that replaces the entry in one step, and its `restore` takes back only the URI it added (`TestConcurrentRegistration`).
- Expired authorization requests were not cleaned during the first minute after the host booted: `RequestManager` compared `time.monotonic()` (seconds since boot) with a last-clean time of 0. It now starts at `-inf`, so the first call cleans.
- Error redirects from `/verify/user` (`authentication_error_redirect`) carry the authorization request's `state` (RFC 6749 4.1.2.1) and append to a `redirect_uri` that already has a query with `&`.
- `python3 server.py -d <config>` crashed (`app.endpoint_context` does not exist); it prints the provider information from `app.server.get_context()` again.
- `auth_error_redirect` builds the error redirect from the client's registered redirect URI instead of the request's `redirect_uri` (SonarCloud open redirect, RFC 6749 4.1.2.1). Only registered URIs were accepted before as well, so behaviour is unchanged.

### Security
- GitHub Actions: the Docker actions of `pipeline.yml` are pinned to full commit SHAs; every workflow has `permissions: {}` at workflow level and read-only permissions per job (`dependencycheck.yml` and `gitleaks.yml` had the default token permissions).
- Log lines no longer contain the client's `client_id` (rejected redirect URI), `request_uri` (unknown request) or the form of an unsupported token request (SonarCloud log injection); `TestLogInjection`.
- Removed `yaml_to_json.py` (unused since the configuration is YAML; it was copied into the image).
- SonarCloud: `views.py` reads the DPoP header with `request.headers.get()`; the reviewed CSRF hotspot in `application.py` (S4502) is documented and marked `# NOSONAR`.
