"""Security helpers shared by the views.

* :func:`session_token` signs the issuance session handed to the issuer
  backend, so the backend can trust ``session_id`` and the requested
  credentials instead of reading them from the query string.
* :func:`backend_api_key_error` protects the endpoints only the issuer
  backend may call (``/preauth_generate``).
"""

import hmac
from typing import Any, Dict, Optional

from cryptojwt.jwt import JWT
from flask import current_app, jsonify, request

#: ``aud`` of the session token; the issuer backend checks it.
SESSION_TOKEN_AUDIENCE = "eudiw-issuer-backend"
#: Seconds the backend has to accept the session token.
SESSION_TOKEN_LIFETIME = 300
#: Placeholder keys from the example configuration; treated as unset.
PLACEHOLDER_API_KEYS = frozenset({"change-me", "changeme", "secret"})


def session_token(
    session_id: str,
    scope: Optional[str] = None,
    authorization_details: Any = None,
    frontend_id: Optional[str] = None,
) -> str:
    """Signs the issuance session handed to the issuer backend.

    Args:
        session_id: Issuance session id.
        scope: Requested scope.
        authorization_details: Requested authorization details.
        frontend_id: Frontend that started the flow.

    Returns:
        A short-lived ES256 JWT signed with the OP key (see ``/static/jwks.json``).
    """
    context = current_app.server.get_context()
    claims: Dict[str, Any] = {"session_id": session_id}
    if scope:
        claims["scope"] = scope
    if authorization_details:
        claims["authorization_details"] = authorization_details
    if frontend_id:
        claims["frontend_id"] = frontend_id
    signer = JWT(context.keyjar, iss=context.issuer, sign_alg="ES256", lifetime=SESSION_TOKEN_LIFETIME)
    return signer.pack(payload=claims, aud=[SESSION_TOKEN_AUDIENCE])


def backend_api_key_error():
    """Checks the ``X-Api-Key`` header sent by the issuer backend.

    Returns:
        ``None`` when the key matches, otherwise the error response: ``503``
        when no key is configured, ``401`` for a missing or wrong key.
    """
    expected = getattr(current_app, "backend_api_key", None)
    if not expected or str(expected) in PLACEHOLDER_API_KEYS:
        current_app.logger.error("backend_api_key is not configured")
        return jsonify({"error": "service_unavailable", "error_description": "API key not configured"}), 503
    candidate = request.headers.get("X-Api-Key") or ""
    if not hmac.compare_digest(candidate.encode(), str(expected).encode()):
        current_app.logger.warning(f"Rejected {request.path}: missing or invalid X-Api-Key")
        return jsonify({"error": "unauthorized", "error_description": "Missing or invalid API key"}), 401
    return None


#: Default limit per client address for each endpoint. Introspection is not
#: limited: all of it comes from the issuer backend's address.
ENDPOINT_LIMITS = {
    "oidc_op.token": "60 per minute",
    "oidc_op.prea_auth": "30 per minute",
    "oidc_op.par_endpoint": "30 per minute",
    "oidc_op.authorization": "30 per minute",
    "oidc_op.verify_user": "30 per minute",
}


def init_rate_limits(app, settings=None):
    """Applies per-client rate limits (``429`` when exceeded).

    Args:
        app: The Flask application, after the views are registered.
        settings: ``rate_limiting`` configuration: ``enabled`` (default
            true), ``storage_uri`` (default ``memory://``),
            ``trusted_proxies`` (reverse proxies whose ``X-Forwarded-For``
            is trusted; 1 behind nginx) and ``limits`` overrides.

    Returns:
        The limiter, or ``None`` when disabled.
    """
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    from werkzeug.middleware.proxy_fix import ProxyFix

    settings = settings or {}
    if settings.get("enabled", True) is False:
        app.logger.warning("Rate limiting is disabled")
        return None
    proxies = int(settings.get("trusted_proxies", 0) or 0)
    if proxies > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=proxies, x_proto=proxies, x_host=proxies)

    def too_many_requests(limit):
        app.logger.warning(f"Rate limit exceeded: {limit.limit}")
        return jsonify({"error": "too_many_requests", "error_description": "Rate limit exceeded"}), 429

    limiter = Limiter(
        get_remote_address,
        app=app,
        storage_uri=settings.get("storage_uri", "memory://"),
        headers_enabled=True,
        on_breach=too_many_requests,
    )
    for endpoint, limit in {**ENDPOINT_LIMITS, **(settings.get("limits") or {})}.items():
        view = app.view_functions.get(endpoint)
        if view is not None:
            app.view_functions[endpoint] = limiter.limit(limit)(view)
    return limiter


#: Parameter / header names whose values are secrets and never logged.
SENSITIVE_NAMES = frozenset(
    {
        "code", "code_verifier", "access_token", "refresh_token", "id_token", "token",
        "client_assertion", "client_secret", "pre-authorized_code", "pre_authorized_code",
        "tx_code", "authorization", "dpop", "cookie", "set-cookie", "jws",
        "oauth-client-attestation", "oauth-client-attestation-pop", "x-api-key", "value",
    }
)


def redact(value):
    """Returns a copy of ``value`` safe to log: secret fields become ``<redacted>``.

    Dicts (and Message objects), lists and URL-like strings with secrets in the
    query are handled; header lists of ``{"name", "value"}`` (cookies) too.
    """
    if hasattr(value, "to_dict") and not isinstance(value, dict):
        try:
            value = value.to_dict()
        except Exception:
            return "<unloggable>"
    if isinstance(value, dict):
        if set(value) >= {"name", "value"}:
            return {"name": value.get("name"), "value": "<redacted>"}
        return {k: "<redacted>" if str(k).lower() in SENSITIVE_NAMES else redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str) and value.lstrip().startswith("{"):
        import json

        try:
            return json.dumps(redact(json.loads(value)))
        except ValueError:
            return "<unloggable>"
    if isinstance(value, str) and "=" in value and ("?" in value or "&" in value):
        from urllib.parse import parse_qsl, urlsplit

        query = urlsplit(value).query if "?" in value else value
        if any(k.lower() in SENSITIVE_NAMES for k, _ in parse_qsl(query)):
            return value.split("?", 1)[0] + "?<redacted query>" if "?" in value else "<redacted>"
    return value
