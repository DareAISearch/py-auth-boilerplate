from typing import Any

import pytest

from py_auth_boilerplate.cache.redis_cache import RedisCache
from py_auth_boilerplate.cache.types import CacheSetManyEntry


class _FakePipeline:
    """Minimal stand-in for the subset of redis-py's pipeline API RedisCache actually calls."""

    def __init__(self, exec_results: list[Any] | None) -> None:
        self._exec_results = exec_results
        self.queued: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def set(self, *args: Any, **kwargs: Any) -> _FakePipeline:
        self.queued.append((args, kwargs))
        return self

    async def execute(self, raise_on_error: bool = True) -> list[Any] | None:
        return self._exec_results


class FakeRedis:
    def __init__(self) -> None:
        self.exec_results: list[Any] | None = []
        self.set_calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.last_pipeline: _FakePipeline | None = None
        self.get_returns: bytes | str | None = None

    async def get(self, key: str) -> bytes | str | None:
        return self.get_returns

    async def set(self, *args: Any, **kwargs: Any) -> str:
        self.set_calls.append((args, kwargs))
        return "OK"

    async def eval(self, *args: Any, **kwargs: Any) -> int:
        return 0

    def pipeline(self) -> _FakePipeline:
        self.last_pipeline = _FakePipeline(self.exec_results)
        return self.last_pipeline


class TestRedisCacheSpecificBehavior:
    async def test_get_decodes_bytes_to_str_when_the_client_has_no_decode_responses(self) -> None:
        # A client constructed without decode_responses=True (i.e. not via RedisCache.from_url)
        # returns bytes -- get() must still satisfy the Cache protocol's str contract.
        fake = FakeRedis()
        fake.get_returns = b"cached-value"
        cache = RedisCache(fake)  # type: ignore[arg-type]
        assert await cache.get("k") == "cached-value"

    async def test_get_passes_through_str_unchanged(self) -> None:
        fake = FakeRedis()
        fake.get_returns = "cached-value"
        cache = RedisCache(fake)  # type: ignore[arg-type]
        assert await cache.get("k") == "cached-value"

    async def test_set_rejects_a_non_positive_ttl_without_ever_calling_the_underlying_client(self) -> None:
        fake = FakeRedis()
        cache = RedisCache(fake)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await cache.set("k", "v", 0)
        with pytest.raises(ValueError):
            await cache.set("k", "v", -1)
        assert len(fake.set_calls) == 0

    async def test_set_many_rejects_if_any_entry_has_a_non_positive_ttl_before_issuing_the_pipeline(
        self,
    ) -> None:
        fake = FakeRedis()
        cache = RedisCache(fake)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            await cache.set_many(
                [
                    CacheSetManyEntry(key="a", value="1", ttl_seconds=60),
                    CacheSetManyEntry(key="b", value="2", ttl_seconds=0),
                ]
            )

    async def test_set_many_raises_when_the_pipeline_reports_a_per_command_failure(self) -> None:
        fake = FakeRedis()
        fake.exec_results = ["OK", RuntimeError("OOM command not allowed")]
        cache = RedisCache(fake)  # type: ignore[arg-type]
        with pytest.raises(RuntimeError, match="pipeline command failed"):
            await cache.set_many(
                [
                    CacheSetManyEntry(key="a", value="1", ttl_seconds=60),
                    CacheSetManyEntry(key="b", value="2", ttl_seconds=60),
                ]
            )

    async def test_set_many_resolves_normally_when_every_pipelined_command_succeeds(self) -> None:
        fake = FakeRedis()
        fake.exec_results = ["OK", "OK"]
        cache = RedisCache(fake)  # type: ignore[arg-type]
        await cache.set_many(
            [
                CacheSetManyEntry(key="a", value="1", ttl_seconds=60),
                CacheSetManyEntry(key="b", value="2", ttl_seconds=60),
            ]
        )

    async def test_set_many_is_a_noop_for_an_empty_list_and_never_touches_the_pipeline(self) -> None:
        fake = FakeRedis()
        fake.exec_results = None
        cache = RedisCache(fake)  # type: ignore[arg-type]
        await cache.set_many([])

    async def test_set_passes_a_sub_second_ttl_as_milliseconds(self) -> None:
        # EX only takes whole seconds and would stretch 0.3s to 1s; PX keeps it at 300ms.
        fake = FakeRedis()
        cache = RedisCache(fake)  # type: ignore[arg-type]
        await cache.set("k", "v", 0.3)
        args, kwargs = fake.set_calls[0]
        assert args == ("k", "v")
        assert kwargs == {"px": 300}

    async def test_set_rounds_a_tiny_ttl_up_to_one_millisecond_rather_than_zero(self) -> None:
        # Redis rejects PX 0 outright.
        fake = FakeRedis()
        cache = RedisCache(fake)  # type: ignore[arg-type]
        await cache.set("k", "v", 0.0001)
        _args, kwargs = fake.set_calls[0]
        assert kwargs["px"] == 1

    async def test_set_converts_seconds_without_float_noise_or_truncation(self) -> None:
        # 4.2 * 1000 is 4200.000000000001 in floating point: must be 4200, not 4201.
        fake = FakeRedis()
        cache = RedisCache(fake)  # type: ignore[arg-type]
        await cache.set("k", "v", 4.2)
        await cache.set("k", "v", 0.0015)
        assert [kwargs["px"] for _args, kwargs in fake.set_calls] == [4200, 2]

    async def test_set_many_passes_each_entrys_ttl_as_milliseconds_in_the_pipeline(self) -> None:
        fake = FakeRedis()
        fake.exec_results = ["OK"]
        cache = RedisCache(fake)  # type: ignore[arg-type]
        await cache.set_many([CacheSetManyEntry(key="a", value="1", ttl_seconds=0.3)])
        assert fake.last_pipeline is not None
        args, kwargs = fake.last_pipeline.queued[0]
        assert args == ("a", "1")
        assert kwargs == {"px": 300}
