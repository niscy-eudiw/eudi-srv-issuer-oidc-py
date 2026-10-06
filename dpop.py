"""DPoP (RFC 9449) sender-constrained access tokens.

The idpyoidc DPoP add-on checks a proof's signature, ``htm`` and ``htu`` but
does not bind the access token to the proof key. This module completes it:

* :func:`verify_proof` validates a DPoP proof (asymmetric ``alg``, public
  ``jwk``, ``htm`` / ``htu``, ``iat`` window, single-use ``jti``) and returns
  the key thumbprint (``jkt``);
* :data:`bindings` remembers which ``jkt`` each issued access token is bound
  to; ``/introspection`` returns it as ``cnf.jkt`` so the issuer backend can
  require a matching proof.
"""

import hashlib
import threading
import time
from typing import Dict, Iterable, Optional, Tuple

from cryptojwt import as_unicode
from cryptojwt.jwk.jwk import key_from_jwk_dict
from cryptojwt.jws.jws import factory

#: Asymmetric algorithms accepted for DPoP proofs.
DPOP_ALGORITHMS = ("ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512", "EdDSA")
#: Accepted proof age (seconds) and clock skew into the future.
MAX_PROOF_AGE = 300
MAX_CLOCK_SKEW = 60
_PRIVATE_JWK_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "k")


class DPoPError(ValueError):
    """Raised for an invalid DPoP proof."""


class _ExpiringSet:
    """Thread-safe set whose entries expire."""

    def __init__(self):
        self._entries: Dict[str, float] = {}
        self._lock = threading.Lock()

    def add_once(self, key: str, ttl: float) -> bool:
        """Adds ``key``; returns False when it is already present."""
        now = time.time()
        with self._lock:
            for k in [k for k, exp in self._entries.items() if exp < now]:
                del self._entries[k]
            if key in self._entries:
                return False
            self._entries[key] = now + ttl
            return True


class TokenBindings:
    """Access token -> bound ``jkt``, kept until the token expires."""

    def __init__(self):
        self._entries: Dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def bind(self, token: str, jkt: str, lifetime: float) -> None:
        now = time.time()
        with self._lock:
            for k in [k for k, (_, exp) in self._entries.items() if exp < now]:
                del self._entries[k]
            self._entries[self._key(token)] = (jkt, now + lifetime)

    def jkt(self, token: str) -> Optional[str]:
        with self._lock:
            entry = self._entries.get(self._key(token))
        if entry is None or entry[1] < time.time():
            return None
        return entry[0]


bindings = TokenBindings()
_seen_jti = _ExpiringSet()


def _strip_query(url: str) -> str:
    return url.split("?", 1)[0].split("#", 1)[0]


def verify_proof(proof: str, method: str, allowed_htu: Iterable[str]) -> str:
    """Validates a DPoP proof sent to the token endpoint.

    Args:
        proof: The ``DPoP`` header value.
        method: HTTP method of the request.
        allowed_htu: URLs the proof may address (the public token endpoint
            URLs, ``allowed_htu`` in the configuration).

    Returns:
        The RFC 7638 thumbprint (``jkt``) of the proof key.

    Raises:
        DPoPError: If the proof is malformed, uses a forbidden algorithm or a
            private key, has a wrong ``htm`` / ``htu``, is too old or in the
            future, or its ``jti`` was already used.
    """
    jws = factory(proof)
    if not jws:
        raise DPoPError("DPoP proof is not a JWS")
    headers = jws.jwt.headers
    if headers.get("typ") != "dpop+jwt":
        raise DPoPError("DPoP proof typ must be dpop+jwt")
    alg = headers.get("alg")
    if alg not in DPOP_ALGORITHMS:
        raise DPoPError(f"DPoP proof alg {alg!r} not allowed")
    jwk = headers.get("jwk")
    if not isinstance(jwk, dict) or any(member in jwk for member in _PRIVATE_JWK_MEMBERS):
        raise DPoPError("DPoP proof must carry a public jwk")
    try:
        key = key_from_jwk_dict(jwk)
        key.deserialize()
        claims = jws.verify_compact(proof, keys=[key], sigalg=alg)
    except Exception as e:
        raise DPoPError(f"DPoP proof signature invalid: {e}") from e

    if claims.get("htm") != method:
        raise DPoPError("DPoP proof htm does not match the request")
    if _strip_query(str(claims.get("htu", ""))) not in {_strip_query(u) for u in allowed_htu}:
        raise DPoPError("DPoP proof htu does not match the token endpoint")
    iat = claims.get("iat")
    now = time.time()
    if not isinstance(iat, (int, float)) or iat > now + MAX_CLOCK_SKEW or iat < now - MAX_PROOF_AGE:
        raise DPoPError("DPoP proof iat outside the accepted window")
    jti = claims.get("jti")
    if not isinstance(jti, str) or not jti:
        raise DPoPError("DPoP proof jti missing")

    jkt = as_unicode(key.thumbprint("SHA-256"))
    if not _seen_jti.add_once(f"{jkt}:{jti}", MAX_PROOF_AGE + MAX_CLOCK_SKEW):
        raise DPoPError("DPoP proof jti already used")
    return jkt
