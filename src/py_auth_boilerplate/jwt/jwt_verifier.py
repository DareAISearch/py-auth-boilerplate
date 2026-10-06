import hashlib
import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from ..cache.types import Cache
from ..errors import AuthError, JwksUnavailableError
from ..http_client import FetchImpl, http_fetch
from ..lock.single_flight import with_single_flight


def _parse_max_age_seconds(cache_control: str | None) -> int | None:
    if not cache_control:
        return None
    for directive in cache_control.split(","):
        name, _, value = directive.partition("=")
        if name.strip().lower() != "max-age":
            continue
        try:
            seconds = int(value.strip())
        except ValueError:
            continue
        if seconds > 0:
            return seconds
    return None


class _JwtVerifierConfigLike(Protocol):
    """Structural shape of the config `create_jwt_verifier` needs.

    Declared as read-only properties (rather than plain attributes) so that both mutable
    config objects and frozen dataclasses like `AuthConfig` satisfy it -- a plain attribute
    in a Protocol requires the implementation's attribute to be settable, which a frozen
    dataclass's fields are not.
    """

    @property
    def jwks_url(self) -> str: ...
    @property
    def service_name(self) -> str: ...
    @property
    def jwks_cache_ttl_seconds(self) -> int: ...
    @property
    def token_cache_max_ttl_seconds(self) -> int: ...
    @property
    def clock_tolerance_seconds(self) -> int: ...


@dataclass
class JwtVerifier:
    verify: Callable[[str], Awaitable[dict[str, Any]]]


def create_jwt_verifier(
    *,
    config: _JwtVerifierConfigLike,
    cache: Cache,
    fetch_impl: FetchImpl | None = None,
) -> JwtVerifier:
    """Verifies inbound JWTs against an IAM service's JWKS. No `issuer` validation is performed.
    A `kid` not found in the currently-cached JWKS document is rejected immediately as unknown; it
    is deliberately NOT retried against a fresh fetch (see README for the key-rotation tradeoff)."""
    fetch = fetch_impl or http_fetch

    fingerprint_seed = f"{config.jwks_url}|{config.service_name}".encode()
    verifier_fingerprint = hashlib.sha256(fingerprint_seed).hexdigest()[:16]

    def token_cache_key(token: str) -> str:
        return f"tok:{verifier_fingerprint}:{hashlib.sha256(token.encode()).hexdigest()}"

    def jwks_document_cache_key() -> str:
        return f"jwks:document:{verifier_fingerprint}"

    def jwks_refresh_lock_key() -> str:
        return f"jwks:refresh:lock:{verifier_fingerprint}"

    async def fetch_and_cache_jwks() -> list[dict[str, Any]]:
        response = await fetch(config.jwks_url)
        if not response.is_success:
            raise JwksUnavailableError(f"JWKS fetch failed: {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise JwksUnavailableError("JWKS response is missing a valid keys array") from exc

        keys = body.get("keys") if isinstance(body, dict) else None
        if not isinstance(keys, list):
            raise JwksUnavailableError("JWKS response is missing a valid keys array")

        ttl_seconds = _parse_max_age_seconds(response.headers.get("cache-control"))
        if ttl_seconds is None:
            ttl_seconds = config.jwks_cache_ttl_seconds
        await cache.set(jwks_document_cache_key(), json.dumps(keys), ttl_seconds)
        return keys

    async def get_jwks() -> list[dict[str, Any]]:
        cached = await cache.get(jwks_document_cache_key())
        if cached is not None:
            return json.loads(cached)  # type: ignore[no-any-return]

        async def poll_for_cached() -> list[dict[str, Any]] | None:
            value = await cache.get(jwks_document_cache_key())
            return json.loads(value) if value is not None else None

        return await with_single_flight(
            cache, jwks_refresh_lock_key(), fetch_and_cache_jwks, poll_for_cached
        )

    async def verify(token: str) -> dict[str, Any]:
        cache_key = token_cache_key(token)
        cached = await cache.get(cache_key)
        if cached is not None:
            cached_payload: dict[str, Any] = json.loads(cached)
            return cached_payload

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("malformed token") from exc
        kid = header.get("kid")
        if not kid:
            raise AuthError("token header missing kid")
        if not isinstance(kid, str):
            raise AuthError("token header kid must be a string")

        jwks = await get_jwks()
        jwk = next((k for k in jwks if isinstance(k, dict) and k.get("kid") == kid), None)
        if jwk is None:
            raise AuthError(f"unknown kid: {kid}")

        try:
            public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise AuthError("JWK did not decode to an RSA public key")
            payload: dict[str, Any] = jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=config.service_name,
                options={"require": ["exp", "aud"]},
                leeway=config.clock_tolerance_seconds,
            )
        except Exception as exc:
            raise AuthError(str(exc) or "token verification failed") from exc

        # A cached verdict must never outlive the token it was computed for.
        ttl = min(payload["exp"] - int(time.time()), config.token_cache_max_ttl_seconds)
        if ttl > 0:
            await cache.set(cache_key, json.dumps(payload), ttl)

        return payload

    return JwtVerifier(verify=verify)
