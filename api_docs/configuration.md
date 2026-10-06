# Configuration

For configuring your locally installed version of the EUDIW Issuer Authorization Server, you need to change the following configurations.

## 1. Service Configuration

Base configuration for the EUDIW Issuer Authorization server is located in ```config.json``.

Parameters that should be changed:

- `domain` (Base url of the service)
- `port` Port number on which the service is running
- `allowed_htu` List of allowed DPoP htu
- `backend_api_key` Key the issuer backend sends in the `X-Api-Key` header to call `/preauth_generate`. It must match `authorization_server.api_key` in the backend configuration. The endpoint answers 503 while it is unset or still `change-me`.

- `trust_validator_url` WIA trust validator URL. Source code available at [eudi-srv-trust-validator](https://github.com/eu-digital-identity-wallet/eudi-srv-trust-validator)
- `status_validator_url` endpoint URL for checking revocation/validity status of Referenced Tokens against a Token Status List. Source code available at [eudi-srv-status-validator-py](https://github.com/eu-digital-identity-wallet/eudi-srv-status-validator-py)
- `trusted_attesters_path` WIA trust validation by pem certificate files path

trust_validator_url and trusted_attesters_path should not be used at the same time.

## 2. Session hand-off to the issuer backend

After an authorization request the server redirects the browser to `authorization_redirect_url` (the backend `/auth_choice`). Besides `token`, `session_id`, `scope` and `authorization_details`, the redirect carries `session_token`: an ES256 JWT signed with the server key (published at `/static/jwks.json`), `aud` `eudiw-issuer-backend`, valid for 5 minutes, with the claims `session_id`, `scope`, `authorization_details` and `frontend_id`. The backend only trusts these signed claims.

A wallet-supplied `issuer_state` is stored with the request but never used as the session id. `/verify/user` only completes an authorization when `username` is the session created for the authorization request in `token`.

Pre-authorized codes can be redeemed for 10 minutes and once only; five wrong `tx_code` attempts revoke the code.
