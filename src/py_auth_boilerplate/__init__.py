from .cache.memory_cache import InMemoryCache
from .cache.redis_cache import RedisCache
from .cache.types import Cache, CacheSetManyEntry
from .claims import UNSET, assert_claim_matches
from .config import AuthConfig, load_auth_config_from_env
from .errors import (
    AuthConfigError,
    AuthError,
    ForbiddenError,
    HttpError,
    JwksUnavailableError,
    UnauthorizedError,
    UpstreamError,
)
from .fastapi import AuthPlugin, create_auth_plugin, register_http_error_handler
from .http_client import FetchImpl, HttpClientOptions, http_fetch
from .jwt.jwt_verifier import JwtVerifier, create_jwt_verifier
from .lock.single_flight import (
    SingleFlightOptions,
    acquire_lock,
    release_lock,
    wait_for_result,
    with_single_flight,
)
from .outbound.token_provider import TokenProvider, create_token_provider

__all__ = [
    "UNSET",
    "AuthConfig",
    "AuthConfigError",
    "AuthError",
    "AuthPlugin",
    "Cache",
    "CacheSetManyEntry",
    "FetchImpl",
    "ForbiddenError",
    "HttpClientOptions",
    "HttpError",
    "InMemoryCache",
    "JwksUnavailableError",
    "JwtVerifier",
    "RedisCache",
    "SingleFlightOptions",
    "TokenProvider",
    "UnauthorizedError",
    "UpstreamError",
    "acquire_lock",
    "assert_claim_matches",
    "create_auth_plugin",
    "create_jwt_verifier",
    "create_token_provider",
    "http_fetch",
    "load_auth_config_from_env",
    "register_http_error_handler",
    "release_lock",
    "wait_for_result",
    "with_single_flight",
]
