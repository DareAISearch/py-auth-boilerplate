# py-auth-boilerplate

Reusable JWT authentication for FastAPI services, designed for multi-instance production
deployments. It covers both directions of service-to-service auth:

- **Inbound** — verify bearer tokens against a JWKS endpoint, with verified-claims caching and
  single-flight stampede protection on JWKS refresh.
- **Outbound** — mint and cache short-lived M2M bearer tokens from an IAM client-credentials
  endpoint, keyed by audience, with the same single-flight protection on token mint.

Everything is built against a small `Cache` protocol rather than a hard Redis dependency, so a
single Redis instance can back inbound verification, outbound minting, and stampede protection
across every replica of a service — or you can supply your own cache implementation entirely.

## What this is not

- **No issuer (`iss`) validation.** Verify `payload["iss"]` yourself after `verify()` returns if
  you need it.
- **No replay protection.** The verified-token cache is a performance cache, not a defense against
  replay — a still-valid token can be presented any number of times within its lifetime.
- **RS256 only.** The signing algorithm is fixed, not negotiated from the token or JWK.
- **Strict clock tolerance by default.** `CLOCK_TOLERANCE_SECONDS` defaults to `0`; raise it if
  your IAM service and this one can drift.
- **No fallback refresh for an unknown `kid`.** The JWKS document is cached as a whole and not
  re-fetched until its TTL lapses. A key rotated in mid-window is rejected as `unknown kid` until
  that TTL naturally expires — size the TTL around how quickly you need rotations to take effect.

## Installing

Not on PyPI yet — install straight from this GitHub repo. Requires Python 3.11+.

```bash
pip install "py-auth-boilerplate @ git+https://github.com/DareAISearch/py-auth-boilerplate.git@v0.1.0"
```

or in `pyproject.toml`:

```toml
dependencies = [
    "py-auth-boilerplate @ git+https://github.com/DareAISearch/py-auth-boilerplate.git@v0.1.0",
]
```

`fastapi` is a hard runtime dependency — installed automatically alongside
`create_auth_plugin`, `create_jwt_verifier`, `create_token_provider`, `RedisCache`, and
`InMemoryCache`.

HTTP requests (JWKS fetch, outbound token minting) are made with
[`httpx2`](https://github.com/pydantic/httpx2), Pydantic Services' maintained successor to
`httpx` (same original author) — not `httpx`, and not a typo.

## Configuration

`load_auth_config_from_env()` parses the environment into an `AuthConfig`, backed by a pydantic
schema. It raises `AuthConfigError` on invalid or missing input rather than exiting the process,
since a library must never `sys.exit` its host. See `.env.example` for a template.

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `IAM_SERVICE_URL` | Yes | — | Base URL of the trusted IAM service. `jwks_url` is derived as `{IAM_SERVICE_URL}/.well-known/jwks.json`. |
| `SERVICE_NAME` | Yes | — | This service's identity: the `aud` expected on inbound tokens, and the `sub` sent on outbound mints. |
| `JWKS_CACHE_TTL_SECONDS` | No | `900` | Fallback JWKS cache TTL, used when the JWKS response has no usable `Cache-Control: max-age`. |
| `TOKEN_CACHE_MAX_TTL_SECONDS` | No | `300` | Cap on how long a verified-token cache entry can live. |
| `CLOCK_TOLERANCE_SECONDS` | No | `0` | Leeway applied to `exp`/`nbf`/`iat` checks. |
| `CLIENT_ID` / `CLIENT_SECRET` | Only for outbound | — | OAuth2 client credentials for minting outbound tokens. |
| `OUTBOUND_TOKEN_MAX_TTL_SECONDS` | No | `3600` | Cap on how long a minted outbound token is cached. |
| `OUTBOUND_TOKEN_SAFETY_MARGIN_SECONDS` | No | `30` | Subtracted from the cached TTL so an in-flight-expiring token is never served. |
| `REDIS_URL` | No | — | Not read by the library itself — a convention for your own `RedisCache.from_url(...)` call. |

## Quick Start

Set the required env vars (full list above): `IAM_SERVICE_URL`, `SERVICE_NAME`, `CLIENT_ID` /
`CLIENT_SECRET` (only if minting outbound tokens), `REDIS_URL`.

Enable everything at once — inbound verification with its error handler, outbound minting, and
claim checks, all sharing one cache:

```python
import os

from fastapi import Depends, FastAPI, Request

from py_auth_boilerplate import (
    UNSET,
    RedisCache,
    assert_claim_matches,
    create_token_provider,
    load_auth_config_from_env,
)
from py_auth_boilerplate.fastapi import create_auth_plugin

config = load_auth_config_from_env()
cache = RedisCache.from_url(os.environ["REDIS_URL"])

app = FastAPI()
# Also registers the library's error handler: HttpError -> {error, message}; anything else ->
# a generic 500 that never leaks internal detail.
plugin = create_auth_plugin(app=app, config=config, cache=cache)
provider = create_token_provider(config=config, cache=cache)


@app.post("/scrape")
async def scrape(request: Request, identity: dict = Depends(plugin.require_auth)) -> dict:
    body = await request.json()
    assert_claim_matches(identity, "webhook_url", body.get("webhook_url", UNSET))

    outbound_token = await provider.get_token(
        "llm-gateway", {"webhook_url": "https://this-service.example.com/webhooks/llm-gateway"}
    )
    return {}
```

The same `cache` instance backs both `create_auth_plugin` and `create_token_provider`, so a
stampede on either path is deduplicated across every instance sharing that cache.

## How it works

### Inbound verification

`require_auth`, the FastAPI dependency `create_auth_plugin` returns, reads the
`Authorization: Bearer <token>` header — missing or malformed is an immediate 401. The token is
then handed to `verify()` (`src/py_auth_boilerplate/jwt/jwt_verifier.py`):

1. The cache key is a hash of the token, fingerprinted by trust config
   (`tok:<sha256(jwks_url|service_name)[:16]>:<sha256(token)>`), so two verifiers with different
   trust configuration never share cached verdicts even against the same cache.
2. A cache hit skips verification entirely — this is a performance cache, not a replay defense.
3. On a miss, the token header is decoded for `kid`.
4. The whole JWKS document is fetched and cached as a single unit, TTL taken from the response's
   `Cache-Control: max-age` or falling back to `JWKS_CACHE_TTL_SECONDS`.
5. A `kid` not present in the cached document is rejected immediately as unknown, with no retry.
6. The JWKS fetch itself is single-flighted behind one global lock, so a burst of concurrent
   misses triggers exactly one fetch.
7. Verification uses PyJWT's `jwt.decode` with `algorithms=["RS256"]`, the configured audience,
   required `exp`/`aud` claims, and the configured clock tolerance.
8. The verified payload is cached with TTL `min(token's remaining lifetime, TOKEN_CACHE_MAX_TTL_SECONDS)`.
9. `AuthError` becomes a 401; anything else (e.g. `JwksUnavailableError`, or the cache backend
   being unreachable) propagates as-is and surfaces as a 500, rather than masquerading as a bad
   token.

### Outbound token minting

`create_token_provider`'s `get_token(aud, custom_claims)`
(`src/py_auth_boilerplate/outbound/token_provider.py`) mints and caches a bearer token from the
IAM's client-credentials endpoint:

1. `CLIENT_ID`/`CLIENT_SECRET` are checked at the top of every call — a service that only reads
   tokens someone else minted still needs these set, since the check runs before the cache.
2. The cache key is `aud` plus a stable hash of `custom_claims`, so different claims for the same
   audience are cached independently, and logically-identical claims built in a different key
   order still share a cache entry.
3. `sub` is always `config.service_name`, sent automatically on every mint request.
4. On mint, the cached TTL is `min(expires_in, OUTBOUND_TOKEN_MAX_TTL_SECONDS) - OUTBOUND_TOKEN_SAFETY_MARGIN_SECONDS`
   — the IAM's actual granted lifetime wins over the configured max.
5. Minting is single-flighted per cache key, the same way JWKS refresh is.

### Single-flight / stampede protection

Both flows share one primitive, `with_single_flight`
(`src/py_auth_boilerplate/lock/single_flight.py`): one caller wins an atomic lock and does the
work; concurrent callers poll the cache for the winner's result, bailing out early if the winner
reports a failure; and if the winner never finishes in time, a waiter does the work itself rather
than block indefinitely. `acquire_lock`, `release_lock`, `wait_for_result`, and
`with_single_flight` are all exported from the package root for reuse against your own
cache-miss stampede scenarios.

### Custom claims

`assert_claim_matches(identity, claim_name, supplied_value)` checks a claim on the caller's own
verified token against a value supplied in a request — e.g. a `webhook_url` a caller can only use
if it's already registered on their credentials. Passing nothing (or the exported `UNSET`
sentinel) is a no-op; an explicit `None` is checked like any other value, so a caller can't bypass
the check by nulling out the field instead of omitting it.

`custom_claims` passed to `get_token()` is sent **nested** under that key in the mint request:

```json
{ "aud": "downstream-service", "sub": "my-service", "exp": 1700000000, "custom_claims": { "webhook_url": "https://me.example.com/hook" } }
```

The IAM service is expected to embed those claims **flat** onto the minted token, so the
downstream service verifying it sees `webhook_url` as a top-level claim, which is what
`assert_claim_matches` reads.

## The `Cache` protocol

```python
class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl_seconds: float) -> None: ...
    async def set_many(self, entries: list[CacheSetManyEntry]) -> None: ...
    async def acquire_lock(self, key: str, ttl_ms: float) -> str | None: ...
    async def release_lock(self, key: str, token: str) -> None: ...
```

It's a `typing.Protocol`, so any object with matching async methods satisfies it structurally.
`RedisCache` (production, cross-process) and `InMemoryCache` (tests, single-instance) both
implement it; supply your own for memcached, DynamoDB, or anything else.

`RedisCache.from_url` forwards straight to `redis.asyncio.Redis.from_url`, so standard redis-py
URL and keyword syntax applies, including `rediss://` for TLS. Call `await cache.aclose()` on
shutdown to release a connection constructed via `from_url()`.

## Error handling

Every error this package raises is one of these classes, all exported from the package root:

| Class | Extends | Status | Raised when |
| --- | --- | --- | --- |
| `AuthConfigError` | `Exception` | — | Invalid/missing env vars, or `get_token()` called without `CLIENT_ID`/`CLIENT_SECRET`. |
| `AuthError` | `Exception` | — | Any inbound verification failure — malformed token, unknown `kid`, bad signature, expired, wrong audience. |
| `JwksUnavailableError` | `Exception` | — | The JWKS endpoint is unreachable or returns an unusable response. Not translated to a 401. |
| `UpstreamError` | `Exception` | — | The IAM's client-credentials endpoint fails to mint a token. |
| `UnauthorizedError` | `HttpError` | 401 | Missing/malformed `Authorization` header, or `verify()` raised `AuthError`. |
| `ForbiddenError` | `HttpError` | 403 | `assert_claim_matches` found a mismatch. |
| `HttpError` | `Exception` | any | Base class carrying `status_code` + `code`. |

`create_auth_plugin(app=app, ...)` registers `register_http_error_handler(app)` automatically,
which installs an exception handler turning any `HttpError` into a flat
`{"error": code, "message": ...}` JSON response. Call `register_http_error_handler` yourself for
a differently-mounted sub-app the plugin wasn't constructed against.

## Full runnable example

`examples/fastapi_server/` is a self-contained FastAPI app playing the IAM service, the resource
server, and the client all at once — no external dependencies:

```bash
pip install -e ".[dev]"
python examples/fastapi_server/server.py
```

## Testing

```bash
pytest                                    # unit tests, no external services needed
REDIS_URL=redis://localhost:6379 pytest   # also runs the RedisCache integration suite
```
