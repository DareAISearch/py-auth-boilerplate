import asyncio

import pytest

from py_auth_boilerplate.cache.memory_cache import InMemoryCache
from py_auth_boilerplate.cache.types import Cache, CacheSetManyEntry

from .cache_contract import CacheContractTests


class TestInMemoryCache(CacheContractTests):
    def make_cache(self) -> Cache:
        return InMemoryCache()


class TestInMemoryCacheSpecificBehavior:
    async def test_set_rejects_a_non_positive_ttl_seconds(self) -> None:
        cache = InMemoryCache()
        with pytest.raises(ValueError):
            await cache.set("k", "v", 0)
        with pytest.raises(ValueError):
            await cache.set("k", "v", -1)

    async def test_set_many_rejects_if_any_entry_has_a_non_positive_ttl_and_writes_nothing(self) -> None:
        cache = InMemoryCache()
        with pytest.raises(ValueError):
            await cache.set_many(
                [
                    CacheSetManyEntry(key="a", value="1", ttl_seconds=60),
                    CacheSetManyEntry(key="b", value="2", ttl_seconds=0),
                ]
            )
        assert await cache.get("a") is None

    async def test_sweeps_expired_entries_on_the_next_write_not_just_on_read(self) -> None:
        cache = InMemoryCache()
        for i in range(5):
            await cache.set(f"short-{i}", "v", 0.02)
        assert cache.size == 5
        await asyncio.sleep(0.06)
        # A read alone doesn't evict (_is_live is lazy/read-only).
        assert await cache.get("short-0") is None
        assert cache.size == 5
        await cache.set("trigger", "v", 60)
        assert cache.size == 1
