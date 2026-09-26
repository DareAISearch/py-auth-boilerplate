import os

import pytest

from py_auth_boilerplate.cache.redis_cache import RedisCache
from py_auth_boilerplate.cache.types import Cache

from .cache_contract import CacheContractTests

_REDIS_URL = os.environ.get("REDIS_URL")


@pytest.mark.skipif(_REDIS_URL is None, reason="requires REDIS_URL")
class TestRedisCacheIntegration(CacheContractTests):
    def make_cache(self) -> Cache:
        assert _REDIS_URL is not None
        return RedisCache.from_url(_REDIS_URL)


@pytest.mark.skipif(_REDIS_URL is None, reason="requires REDIS_URL")
async def test_aclose_releases_the_connection_without_raising() -> None:
    assert _REDIS_URL is not None
    cache = RedisCache.from_url(_REDIS_URL)
    await cache.set("close-test-key", "value", 60)
    await cache.aclose()
