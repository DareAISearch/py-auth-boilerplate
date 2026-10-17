import os
import uuid

import pytest

from py_auth_boilerplate.cache.redis_cache import RedisCache
from py_auth_boilerplate.cache.types import Cache, CacheSetManyEntry

from .cache_contract import CacheContractTests

_REDIS_URL = os.environ.get("REDIS_URL")


class _NamespacedCache:
    """Runs every key through a per-instance random prefix, so each contract test sees an empty
    cache even though they all share one Redis. Cheaper and safer than FLUSHDB, which would wipe
    whatever database REDIS_URL points at."""

    def __init__(self, inner: RedisCache) -> None:
        self._inner = inner
        self._prefix = f"py-auth-boilerplate-test:{uuid.uuid4()}:"

    async def get(self, key: str) -> str | None:
        return await self._inner.get(self._prefix + key)

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        await self._inner.set(self._prefix + key, value, ttl_seconds)

    async def set_many(self, entries: list[CacheSetManyEntry]) -> None:
        await self._inner.set_many(
            [
                CacheSetManyEntry(key=self._prefix + e.key, value=e.value, ttl_seconds=e.ttl_seconds)
                for e in entries
            ]
        )

    async def acquire_lock(self, key: str, ttl_ms: float) -> str | None:
        return await self._inner.acquire_lock(self._prefix + key, ttl_ms)

    async def release_lock(self, key: str, token: str) -> None:
        await self._inner.release_lock(self._prefix + key, token)


@pytest.mark.skipif(_REDIS_URL is None, reason="requires REDIS_URL")
class TestRedisCacheIntegration(CacheContractTests):
    def make_cache(self) -> Cache:
        assert _REDIS_URL is not None
        return _NamespacedCache(RedisCache.from_url(_REDIS_URL))


@pytest.mark.skipif(_REDIS_URL is None, reason="requires REDIS_URL")
async def test_aclose_releases_the_connection_without_raising() -> None:
    assert _REDIS_URL is not None
    cache = RedisCache.from_url(_REDIS_URL)
    await cache.set("close-test-key", "value", 60)
    await cache.aclose()
