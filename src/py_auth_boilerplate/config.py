import re
from collections.abc import Mapping
from dataclasses import dataclass
from os import environ as _environ

from pydantic import BaseModel, Field, ValidationError

from .errors import AuthConfigError

_ENV_KEYS = (
    "IAM_SERVICE_URL",
    "SERVICE_NAME",
    "JWKS_CACHE_TTL_SECONDS",
    "TOKEN_CACHE_MAX_TTL_SECONDS",
    "CLOCK_TOLERANCE_SECONDS",
    "CLIENT_ID",
    "CLIENT_SECRET",
    "OUTBOUND_TOKEN_MAX_TTL_SECONDS",
    "OUTBOUND_TOKEN_SAFETY_MARGIN_SECONDS",
)


class _AuthEnvSchema(BaseModel):
    IAM_SERVICE_URL: str = Field(min_length=1)
    SERVICE_NAME: str = Field(min_length=1)

    JWKS_CACHE_TTL_SECONDS: int = Field(default=900, gt=0)
    TOKEN_CACHE_MAX_TTL_SECONDS: int = Field(default=300, gt=0)
    CLOCK_TOLERANCE_SECONDS: int = Field(default=0, ge=0)

    CLIENT_ID: str | None = Field(default=None, min_length=1)
    CLIENT_SECRET: str | None = Field(default=None, min_length=1)
    OUTBOUND_TOKEN_MAX_TTL_SECONDS: int = Field(default=3600, gt=0)
    OUTBOUND_TOKEN_SAFETY_MARGIN_SECONDS: int = Field(default=30, ge=0)


@dataclass(frozen=True)
class AuthConfig:
    iam_service_url: str
    jwks_url: str
    service_name: str
    jwks_cache_ttl_seconds: int
    token_cache_max_ttl_seconds: int
    clock_tolerance_seconds: int

    client_id: str | None
    client_secret: str | None
    outbound_token_max_ttl_seconds: int
    outbound_token_safety_margin_seconds: int


def _collect(env: Mapping[str, str]) -> dict[str, str]:
    return {key: env[key] for key in _ENV_KEYS if env.get(key) is not None}


def load_auth_config_from_env(env: Mapping[str, str] | None = None) -> AuthConfig:
    if env is None:
        env = _environ

    try:
        parsed = _AuthEnvSchema.model_validate(_collect(env))
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(str(part) for part in issue['loc'])}: {issue['msg']}" for issue in exc.errors()
        )
        raise AuthConfigError(f"Invalid auth environment configuration: {details}") from exc

    iam_service_url = re.sub(r"/+$", "", parsed.IAM_SERVICE_URL)

    return AuthConfig(
        iam_service_url=iam_service_url,
        jwks_url=f"{iam_service_url}/.well-known/jwks.json",
        service_name=parsed.SERVICE_NAME,
        jwks_cache_ttl_seconds=parsed.JWKS_CACHE_TTL_SECONDS,
        token_cache_max_ttl_seconds=parsed.TOKEN_CACHE_MAX_TTL_SECONDS,
        clock_tolerance_seconds=parsed.CLOCK_TOLERANCE_SECONDS,
        client_id=parsed.CLIENT_ID,
        client_secret=parsed.CLIENT_SECRET,
        outbound_token_max_ttl_seconds=parsed.OUTBOUND_TOKEN_MAX_TTL_SECONDS,
        outbound_token_safety_margin_seconds=parsed.OUTBOUND_TOKEN_SAFETY_MARGIN_SECONDS,
    )
