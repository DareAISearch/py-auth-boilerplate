import asyncio
import time

import pytest

from py_auth_boilerplate.cache.memory_cache import InMemoryCache
from py_auth_boilerplate.lock.single_flight import (
    SingleFlightOptions,
    acquire_lock,
    release_lock,
    wait_for_result,
    with_single_flight,
)


class TestAcquireReleaseLock:
    async def test_acquire_lock_succeeds_when_free_and_returns_a_token(self) -> None:
        cache = InMemoryCache()
        token = await acquire_lock(cache, "lock:a")
        assert isinstance(token, str)
        assert token and len(token) > 0

    async def test_acquire_lock_fails_returns_none_when_already_held(self) -> None:
        cache = InMemoryCache()
        first = await acquire_lock(cache, "lock:a")
        assert first is not None
        second = await acquire_lock(cache, "lock:a")
        assert second is None

    async def test_acquire_lock_succeeds_again_once_the_ttl_has_expired(self) -> None:
        cache = InMemoryCache()
        await acquire_lock(cache, "lock:a", 10)
        await asyncio.sleep(0.03)
        second = await acquire_lock(cache, "lock:a", 10)
        assert second is not None

    async def test_release_lock_removes_the_lock_when_the_token_matches(self) -> None:
        cache = InMemoryCache()
        token = await acquire_lock(cache, "lock:a")
        assert token is not None
        await release_lock(cache, "lock:a", token)
        reacquired = await acquire_lock(cache, "lock:a")
        assert reacquired is not None

    async def test_release_lock_does_not_remove_the_lock_when_the_token_does_not_match(self) -> None:
        cache = InMemoryCache()
        await acquire_lock(cache, "lock:a")
        await release_lock(cache, "lock:a", "wrong-token")
        second = await acquire_lock(cache, "lock:a")
        assert second is None


class TestWaitForResult:
    async def test_returns_the_value_as_soon_as_check_produces_one(self) -> None:
        calls = 0

        async def check() -> str | None:
            nonlocal calls
            calls += 1
            return "ready" if calls >= 3 else None

        result = await wait_for_result(check, attempts=10, interval_ms=1)
        assert result == "ready"
        assert calls == 3

    async def test_returns_none_after_exhausting_all_attempts(self) -> None:
        async def check() -> None:
            return None

        result = await wait_for_result(check, attempts=3, interval_ms=1)
        assert result is None


class TestWithSingleFlight:
    async def test_winner_acquires_the_lock_runs_do_work_once_and_releases_the_lock(self) -> None:
        cache = InMemoryCache()
        do_work_calls = 0

        async def do_work() -> str:
            nonlocal do_work_calls
            do_work_calls += 1
            return "computed"

        async def poll_for_cached() -> None:
            return None

        result = await with_single_flight(cache, "lock:x", do_work, poll_for_cached)
        assert result == "computed"
        assert do_work_calls == 1
        assert await cache.acquire_lock("lock:x", 5000) is not None

    async def test_explicit_zero_wait_attempts_and_interval_are_honored_not_replaced_by_defaults(
        self,
    ) -> None:
        # 0 is falsy in Python -- a naive `opts.x or DEFAULT` would silently replace an explicit
        # 0 with the library defaults (100 attempts / 200ms), turning an immediate fallback into
        # a ~20s wait.
        cache = InMemoryCache()
        await cache.acquire_lock("lock:x", 5000)

        async def do_work() -> str:
            return "self-computed"

        async def poll_for_cached() -> None:
            return None

        opts = SingleFlightOptions(wait_attempts=0, wait_interval_ms=0)
        start = time.monotonic()
        result = await with_single_flight(cache, "lock:x", do_work, poll_for_cached, opts)
        elapsed = time.monotonic() - start

        assert result == "self-computed"
        assert elapsed < 1.0

    async def test_a_loser_that_finds_a_cached_value_via_polling_never_calls_do_work(self) -> None:
        cache = InMemoryCache()
        await cache.acquire_lock("lock:x", 5000)
        do_work_calls = 0

        async def do_work() -> str:
            nonlocal do_work_calls
            do_work_calls += 1
            return "should not run"

        async def poll_for_cached() -> str:
            return "from-cache"

        opts = SingleFlightOptions(wait_attempts=5, wait_interval_ms=1)
        result = await with_single_flight(cache, "lock:x", do_work, poll_for_cached, opts)
        assert result == "from-cache"
        assert do_work_calls == 0

    async def test_a_loser_whose_poll_times_out_does_the_work_itself_rather_than_block_indefinitely(
        self,
    ) -> None:
        cache = InMemoryCache()
        await cache.acquire_lock("lock:x", 5000)
        do_work_calls = 0

        async def do_work() -> str:
            nonlocal do_work_calls
            do_work_calls += 1
            return "self-computed"

        async def poll_for_cached() -> None:
            return None

        opts = SingleFlightOptions(wait_attempts=5, wait_interval_ms=1)
        result = await with_single_flight(cache, "lock:x", do_work, poll_for_cached, opts)
        assert result == "self-computed"
        assert do_work_calls == 1

    async def test_the_winner_writes_a_failure_marker_still_propagates_and_still_releases_the_lock(
        self,
    ) -> None:
        cache = InMemoryCache()

        async def do_work() -> str:
            raise RuntimeError("boom")

        async def poll_for_cached() -> None:
            return None

        with pytest.raises(RuntimeError, match="boom"):
            await with_single_flight(cache, "lock:fail", do_work, poll_for_cached)
        assert await cache.get("lock:fail:failed") is not None
        assert await cache.acquire_lock("lock:fail", 1000) is not None

    async def test_a_loser_bails_out_of_polling_as_soon_as_it_sees_a_failure_marker(self) -> None:
        cache = InMemoryCache()
        lock_key = "lock:fail-fast"
        await cache.acquire_lock(lock_key, 5000)

        async def _fail_shortly() -> None:
            await asyncio.sleep(0.03)
            await cache.set(f"{lock_key}:failed", "1", 2)

        asyncio.ensure_future(_fail_shortly())

        do_work_calls = 0

        async def do_work() -> str:
            nonlocal do_work_calls
            do_work_calls += 1
            return "self-computed"

        async def poll_for_cached() -> None:
            return None

        start = time.monotonic()
        result = await with_single_flight(
            cache,
            lock_key,
            do_work,
            poll_for_cached,
            SingleFlightOptions(wait_attempts=50, wait_interval_ms=10),
        )
        elapsed = time.monotonic() - start

        assert result == "self-computed"
        assert do_work_calls == 1
        assert elapsed < 0.25
