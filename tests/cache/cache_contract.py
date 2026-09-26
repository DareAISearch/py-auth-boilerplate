import asyncio

from py_auth_boilerplate.cache.types import Cache, CacheSetManyEntry


class CacheContractTests:
    """Not itself collected as a test module -- this file isn't named test_*.py. Subclass and
    override make_cache()."""

    def make_cache(self) -> Cache:
        raise NotImplementedError

    async def test_get_returns_none_for_a_missing_key(self) -> None:
        cache = self.make_cache()
        assert await cache.get("missing") is None

    async def test_get_returns_a_value_that_was_set(self) -> None:
        cache = self.make_cache()
        await cache.set("k", "v", 60)
        assert await cache.get("k") == "v"

    async def test_expires_a_value_after_its_ttl_elapses(self) -> None:
        cache = self.make_cache()
        await cache.set("k", "v", 0.05)
        await asyncio.sleep(0.1)
        assert await cache.get("k") is None

    async def test_set_many_writes_every_entry_so_a_subsequent_get_sees_all_of_them(self) -> None:
        cache = self.make_cache()
        await cache.set_many(
            [
                CacheSetManyEntry(key="a", value="1", ttl_seconds=60),
                CacheSetManyEntry(key="b", value="2", ttl_seconds=60),
            ]
        )
        assert await cache.get("a") == "1"
        assert await cache.get("b") == "2"

    async def test_set_many_is_a_noop_for_an_empty_list(self) -> None:
        cache = self.make_cache()
        await cache.set_many([])

    async def test_acquire_lock_succeeds_when_free_and_returns_a_non_empty_token(self) -> None:
        cache = self.make_cache()
        token = await cache.acquire_lock("lock:a", 5000)
        assert isinstance(token, str)
        assert token and len(token) > 0

    async def test_acquire_lock_fails_returns_none_when_already_held(self) -> None:
        cache = self.make_cache()
        first = await cache.acquire_lock("lock:a", 5000)
        assert first is not None
        second = await cache.acquire_lock("lock:a", 5000)
        assert second is None

    async def test_acquire_lock_succeeds_again_once_the_ttl_has_expired(self) -> None:
        cache = self.make_cache()
        await cache.acquire_lock("lock:a", 10)
        await asyncio.sleep(0.04)
        second = await cache.acquire_lock("lock:a", 5000)
        assert second is not None

    async def test_release_removes_the_lock_when_the_token_matches(self) -> None:
        cache = self.make_cache()
        token = await cache.acquire_lock("lock:a", 5000)
        assert token is not None
        await cache.release_lock("lock:a", token)
        reacquired = await cache.acquire_lock("lock:a", 5000)
        assert reacquired is not None

    async def test_release_does_not_remove_the_lock_when_the_token_does_not_match(self) -> None:
        cache = self.make_cache()
        await cache.acquire_lock("lock:a", 5000)
        await cache.release_lock("lock:a", "wrong-token")
        second = await cache.acquire_lock("lock:a", 5000)
        assert second is None
