"""Regression tests for the 2026-07 security assessment findings."""

import base64
import hashlib
import json
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptojwt.jwt import JWT

from conftest import BACKEND_API_KEY

import application

CLIENT_ID = "wallet-test"
REDIRECT_URI = "https://wallet.test/cb"
VERIFIER = "verifier-" + "x" * 50
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


def _authorize(client, **extra):
    """Runs a non-PAR authorization request; returns the backend redirect query."""
    args = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "eu.europa.ec.eudi.pid_mdoc",
        "state": "st",
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        **extra,
    }
    response = client.get("/authorization", query_string=args)
    assert response.status_code == 302, response.data
    location = response.headers["Location"]
    assert location.startswith("https://backend.test/auth_choice?")
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


def _claims(app, token):
    context = app.server.get_context()
    return JWT(context.keyjar, allowed_sign_algs=["ES256"]).unpack(token)


class TestSessionHandOff:
    """AUTH-VULN-01 / AUTHZ-VULN-01: the backend trusted session_id from the query."""

    def test_redirect_carries_signed_session_token(self, app, client):
        query = _authorize(client)
        claims = _claims(app, query["session_token"])
        assert claims["session_id"] == query["session_id"]
        assert claims["scope"] == "eu.europa.ec.eudi.pid_mdoc"
        assert claims["aud"] == ["eudiw-issuer-backend"]
        assert claims["exp"] - claims["iat"] <= 300

    def test_session_token_cannot_be_forged(self, app, client):
        query = _authorize(client)
        header, payload, signature = query["session_token"].split(".")
        forged = json.loads(base64.urlsafe_b64decode(payload + "=="))
        forged["session_id"] = "attacker-chosen"
        forged_payload = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
        with pytest.raises(Exception):
            _claims(app, f"{header}.{forged_payload}.{signature}")

    def test_issuer_state_never_becomes_the_session_id(self, client):
        query = _authorize(client, issuer_state="attacker-chosen")
        assert query["session_id"] != "attacker-chosen"
        stored = application.request_manager.get_request(session_id=query["session_id"])
        assert stored.issuer_state == "attacker-chosen"

    def test_par_issuer_state_never_becomes_the_session_id(self, client):
        response = client.post(
            "/pushed_authorization",
            data={
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "response_type": "code",
                "scope": "eu.europa.ec.eudi.pid_mdoc",
                "code_challenge": CHALLENGE,
                "code_challenge_method": "S256",
                "issuer_state": "victim-session",
            },
        )
        assert response.status_code in (200, 201), response.data
        assert application.request_manager.get_request(session_id="victim-session") is None

    def test_verify_user_rejects_another_session(self, client):
        mine = _authorize(client)
        other = _authorize(client, state="other-state")
        response = client.get(
            "/verify/user", query_string={"token": mine["token"], "username": other["session_id"]}
        )
        assert response.status_code == 400
        assert b"Session mismatch" in response.data

    def test_verify_user_completes_its_own_session(self, client):
        mine = _authorize(client)
        response = client.get(
            "/verify/user", query_string={"token": mine["token"], "username": mine["session_id"]}
        )
        assert response.status_code == 302
        assert response.headers["Location"].startswith(REDIRECT_URI)
        assert "code=" in response.headers["Location"]


class TestPreAuthorizedCodes:
    """Anyone could mint pre-authorized codes; the 5-digit tx_code had no attempt limit."""

    def _generate(self, client, key=BACKEND_API_KEY):
        headers = {"X-Api-Key": key} if key else {}
        return client.post("/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc"}, headers=headers)

    @pytest.mark.parametrize("key", [None, "wrong"])
    def test_preauth_generate_requires_the_backend_key(self, client, key):
        assert self._generate(client, key).status_code == 401

    def test_preauth_generate_fails_closed_without_configured_key(self, app, client):
        app.backend_api_key = "change-me"
        assert self._generate(client).status_code == 503

    def test_preauth_generate_with_key(self, client):
        body = self._generate(client).get_json()
        assert 10000 <= body["tx_code"] <= 99999 and body["preauth_code"] and body["session_id"]

    def _redeem(self, client, code, tx_code):
        return client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": code,
                "tx_code": tx_code,
            },
        )

    def test_unknown_code_is_400_not_500(self, client):
        assert self._redeem(client, "unknown", "12345").status_code == 400

    def test_non_numeric_tx_code_is_400(self, client):
        body = self._generate(client).get_json()
        assert self._redeem(client, body["preauth_code"], "abcde").status_code == 400

    def test_code_revoked_after_five_wrong_tx_codes(self, client):
        body = self._generate(client).get_json()
        wrong = "00000" if body["tx_code"] != 0 else "11111"
        for _ in range(5):
            assert self._redeem(client, body["preauth_code"], wrong).status_code == 400
        response = self._redeem(client, body["preauth_code"], str(body["tx_code"]))
        assert response.status_code == 400
        assert "invalid or expired" in response.get_json()["description"]

    def test_code_is_single_use(self, client):
        body = self._generate(client).get_json()
        first = self._redeem(client, body["preauth_code"], str(body["tx_code"]))
        assert first.status_code == 200, first.data
        assert self._redeem(client, body["preauth_code"], str(body["tx_code"])).status_code == 400

    def test_code_expires(self, client):
        import datetime

        body = self._generate(client).get_json()
        stored = application.request_manager.get_request(session_id=body["session_id"])
        stored.preauth_expiry_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        assert self._redeem(client, body["preauth_code"], str(body["tx_code"])).status_code == 400


class TestRateLimits:
    def test_token_endpoint_throttled(self, app):
        from security import init_rate_limits

        init_rate_limits(app, {"limits": {"oidc_op.token": "3 per minute"}})
        client = app.test_client()
        codes = [client.post("/token", data={"grant_type": "x"}).status_code for _ in range(5)]
        assert codes[:3] == [400, 400, 400] and codes[3:] == [429, 429]


def _dpop_proof(key, htu="https://backend.dev.issuer.eudiw.dev/oidc/token", htm="POST", iat=None, alg="ES256", jti=None):
    import time
    import uuid

    import jwt as pyjwt

    public = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    return pyjwt.encode(
        {"jti": jti or str(uuid.uuid4()), "htm": htm, "htu": htu, "iat": int(iat or time.time())},
        key,
        algorithm=alg,
        headers={"typ": "dpop+jwt", "jwk": public},
    )


def _jkt(key):
    import jwt as pyjwt

    jwk = json.loads(pyjwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


class TestDpopBinding:
    """AUTH-VULN-07: DPoP-bound tokens were accepted as plain bearer tokens."""

    @pytest.fixture
    def key(self):
        from cryptography.hazmat.primitives.asymmetric import ec

        return ec.generate_private_key(ec.SECP256R1())

    def _preauth_token(self, client, key, proof=None):
        body = client.post(
            "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc"}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        headers = {"DPoP": proof if proof is not None else _dpop_proof(key)}
        return client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": body["preauth_code"],
                "tx_code": str(body["tx_code"]),
            },
            headers=headers,
        )

    def test_token_bound_and_introspection_reports_jkt(self, client, key):
        response = self._preauth_token(client, key)
        assert response.status_code == 200, response.data
        body = response.get_json()
        assert body["token_type"] == "DPoP"
        introspection = client.post(
            "/introspection", data={"token": body["access_token"]}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        assert introspection["active"] is True
        assert introspection["cnf"] == {"jkt": _jkt(key)}

    def test_introspection_requires_the_backend_key(self, client, key):
        token = self._preauth_token(client, key).get_json()["access_token"]
        assert client.post("/introspection", data={"token": token}).status_code == 401

    @pytest.mark.parametrize(
        "variant",
        ["replayed", "old", "future", "wrong_method", "wrong_htu", "hmac"],
    )
    def test_invalid_proofs_rejected(self, client, key, variant):
        import time

        if variant == "replayed":
            proof = _dpop_proof(key, jti="fixed-jti")
            assert self._preauth_token(client, key, proof).status_code == 200
        elif variant == "old":
            proof = _dpop_proof(key, iat=time.time() - 3600)
        elif variant == "future":
            proof = _dpop_proof(key, iat=time.time() + 3600)
        elif variant == "wrong_method":
            proof = _dpop_proof(key, htm="GET")
        elif variant == "wrong_htu":
            proof = _dpop_proof(key, htu="https://attacker.test/token")
        else:
            import jwt as pyjwt

            proof = pyjwt.encode(
                {"jti": "j", "htm": "POST", "htu": "https://backend.dev.issuer.eudiw.dev/oidc/token", "iat": int(time.time())},
                "secret-secret-secret-secret-secret",
                algorithm="HS256",
                headers={"typ": "dpop+jwt", "jwk": {"kty": "oct", "k": "c2VjcmV0"}},
            )
        response = self._preauth_token(client, key, proof)
        assert response.status_code == 400
        assert response.get_json()["error"] == "invalid_dpop_proof"


class TestLogRedaction:
    """Codes, tokens and tx_codes were written to the logs."""

    def test_redact(self):
        from security import redact

        logged = str(
            redact(
                {
                    "headers": {"authorization": "DPoP secret-at", "dpop": "proof", "user-agent": "w"},
                    "cookie": [{"name": "sid", "value": "secret-cookie"}],
                    "form": {"code": "secret-code", "code_verifier": "secret-v", "grant_type": "authorization_code"},
                    "response": {"access_token": "secret-at2", "token_type": "DPoP", "tx_code": 12345},
                    "redirect": "https://wallet.test/cb?code=secret-code2&state=s",
                }
            )
        )
        for secret in ("secret-at", "proof", "secret-cookie", "secret-code", "secret-v", "secret-at2", "12345", "secret-code2"):
            assert secret not in logged
        assert "authorization_code" in logged and "'user-agent': 'w'" in logged

    def test_token_flow_logs_no_secrets(self, client, caplog):
        import logging

        caplog.set_level(logging.DEBUG)
        body = client.post(
            "/preauth_generate", data={"scope": "eu.europa.ec.eudi.pid_mdoc"}, headers={"X-Api-Key": BACKEND_API_KEY}
        ).get_json()
        token = client.post(
            "/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                "pre-authorized_code": body["preauth_code"],
                "tx_code": str(body["tx_code"]),
            },
        ).get_json()
        text = caplog.text
        assert token["access_token"] not in text
        assert body["preauth_code"] not in text
