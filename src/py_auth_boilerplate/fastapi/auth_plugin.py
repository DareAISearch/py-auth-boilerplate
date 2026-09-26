import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..cache.types import Cache
from ..errors import AuthError, HttpError, UnauthorizedError
from ..http_client import FetchImpl
from ..jwt.jwt_verifier import _JwtVerifierConfigLike, create_jwt_verifier

_logger = logging.getLogger(__name__)


@dataclass
class AuthPlugin:
    require_auth: Callable[[Request], Awaitable[dict[str, Any]]]
    verify: Callable[[str], Awaitable[dict[str, Any]]]


def create_auth_plugin(
    *,
    app: FastAPI,
    config: _JwtVerifierConfigLike,
    cache: Cache,
    fetch_impl: FetchImpl | None = None,
) -> AuthPlugin:
    """Builds a FastAPI dependency that verifies the Authorization bearer token on every request
    it guards: `Depends(require_auth)`. Also registers `register_http_error_handler(app)` on
    `app` -- call it again yourself for a differently-mounted sub-app."""
    register_http_error_handler(app)
    verifier = create_jwt_verifier(config=config, cache=cache, fetch_impl=fetch_impl)

    async def require_auth(request: Request) -> dict[str, Any]:
        header = request.headers.get("authorization")
        if not header or not header.startswith("Bearer "):
            raise UnauthorizedError("missing bearer token")

        token = header[len("Bearer ") :]
        try:
            identity = await verifier.verify(token)
        except AuthError as exc:
            # The real failure reason is logged server-side only -- returning it to the caller
            # would let them fingerprint which check failed.
            _logger.warning("token verification failed: %s", exc)
            raise UnauthorizedError() from exc

        request.state.identity = identity
        return identity

    return AuthPlugin(require_auth=require_auth, verify=verifier.verify)


def register_http_error_handler(app: FastAPI) -> None:
    @app.exception_handler(HttpError)
    async def _handle_http_error(_request: Request, exc: HttpError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.code, "message": str(exc)})
