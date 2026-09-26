import base64
import hashlib
import json
import math
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from ..cache.types import Cache
from ..errors import AuthConfigError, UpstreamError
from ..http_client import FetchImpl, http_fetch
from ..lock.single_flight import with_single_flight


class _TokenProviderConfigLike(Protocol):
    iam_service_url: str
    service_name: str
    client_id: str | None
    client_secret: str | None
    outbound_token_max_ttl_seconds: int
    outbound_token_safety_margin_seconds: int


@dataclass
class TokenProvider:
    get_token: Callable[..., Awaitable[str]]


@dataclass(frozen=True)
class _OutboundCredentials:
    client_id: str
    client_secret: str


# custom_claims is caller-supplied and arbitrarily shaped; a depth cap turns a pathological input
# into a clear ValueError instead of a RecursionError.
_MAX_STABLE_STRINGIFY_DEPTH = 20


def _check_stable_stringify_depth(value: Any, depth: int = 0) -> None:
    if isinstance(value, dict):
        children: Any = value.values()
    elif isinstance(value, (list, tuple)):
        children = value
    else:
        return
    if depth > _MAX_STABLE_STRINGIFY_DEPTH:
        raise ValueError("customClaims is nested too deeply to cache (max depth exceeded)")
    for child in children:
        _check_stable_stringify_depth(child, depth + 1)


def _stable_stringify(value: Any) -> str:
    _check_stable_stringify_depth(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=True)


# Matches ts's JSON.stringify: coerce NaN/Infinity to null on the wire, not json.dumps's raw
# literals. Cache-key hashing (above) is unaffected.
def _sanitize_for_wire(value: Any) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {k: _sanitize_for_wire(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_for_wire(v) for v in value]
    return value


def create_token_provider(
    *,
    config: _TokenProviderConfigLike,
    cache: Cache,
    fetch_impl: FetchImpl | None = None,
) -> TokenProvider:
    """Mints and caches short-lived bearer tokens from an IAM client-credentials endpoint, keyed
    by both audience (aud) and custom_claims. Every mint request sends `sub: config.service_name`
    automatically."""
    fetch = fetch_impl or http_fetch

    def require_outbound_config() -> _OutboundCredentials:
        client_id, client_secret = config.client_id, config.client_secret
        if not client_id or not client_secret:
            missing = [
                name
                for value, name in (
                    (client_id, "clientId (CLIENT_ID)"),
                    (client_secret, "clientSecret (CLIENT_SECRET)"),
                )
                if not value
            ]
            raise AuthConfigError(
                "create_token_provider: get_token() requires outbound config that wasn't "
                f"supplied: {', '.join(missing)}."
            )
        return _OutboundCredentials(client_id, client_secret)

    # Fingerprinted by (iam_service_url, client_id) so callers sharing one cache can't reuse each
    # other's token.
    def cache_key(fingerprint: str, aud: str, custom_claims: dict[str, Any] | None = None) -> str:
        if custom_claims is None:
            return f"iam_token:{fingerprint}:{aud}"
        digest = hashlib.sha256(_stable_stringify(custom_claims).encode()).hexdigest()
        return f"iam_token:{fingerprint}:{aud}:{digest}"

    async def mint(
        outbound: _OutboundCredentials, aud: str, key: str, custom_claims: dict[str, Any] | None
    ) -> str:
        basic_auth = base64.b64encode(f"{outbound.client_id}:{outbound.client_secret}".encode()).decode()
        exp = int(time.time()) + config.outbound_token_max_ttl_seconds

        body: dict[str, Any] = {"aud": aud, "sub": config.service_name, "exp": exp}
        if custom_claims is not None:
            body["custom_claims"] = _sanitize_for_wire(custom_claims)

        response = await fetch(
            f"{config.iam_service_url}/token",
            {
                "method": "POST",
                "headers": {"Authorization": f"Basic {basic_auth}", "Content-Type": "application/json"},
                "content": json.dumps(body),
            },
        )

        if not response.is_success:
            raise UpstreamError(f"IAM token mint failed for aud={aud}: {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise UpstreamError(
                f"IAM token mint returned a malformed response for aud={aud}: invalid JSON"
            ) from exc
        access_token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(access_token, str) or len(access_token) == 0:
            raise UpstreamError(
                f"IAM token mint returned a malformed response for aud={aud}: missing access_token"
            )

        expires_in = payload.get("expires_in")
        if (
            isinstance(expires_in, bool)
            or not isinstance(expires_in, (int, float))
            or not math.isfinite(expires_in)
        ):
            raise UpstreamError(
                f"IAM token mint returned a malformed response for aud={aud}: invalid expires_in"
            )

        # Cache for the IAM's actual granted expires_in, not our own max -- it can grant less.
        max_ttl = config.outbound_token_max_ttl_seconds
        ttl = min(expires_in, max_ttl) - config.outbound_token_safety_margin_seconds
        if ttl > 0:
            await cache.set(key, access_token, ttl)
        return access_token

    async def get_token(aud: str, custom_claims: dict[str, Any] | None = None) -> str:
        outbound = require_outbound_config()
        fingerprint = hashlib.sha256(
            f"{config.iam_service_url}|{outbound.client_id}".encode()
        ).hexdigest()[:16]

        key = cache_key(fingerprint, aud, custom_claims)
        cached = await cache.get(key)
        if cached is not None:
            return cached

        return await with_single_flight(
            cache,
            f"{key}:lock",
            lambda: mint(outbound, aud, key, custom_claims),
            lambda: cache.get(key),
        )

    return TokenProvider(get_token=get_token)
