import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar

from ..cache.types import Cache

_logger = logging.getLogger(__name__)

T = TypeVar("T")

# Must comfortably exceed http_client's DEFAULT_TIMEOUT_SECONDS (10s), or the lock could expire
# mid-flight and a waiter re-acquire it while the original holder is still working.
_LOCK_TTL_MS = 15_000
_WAIT_INTERVAL_MS = 200
# Must comfortably exceed LOCK_TTL_MS, or a waiter gives up and redoes the holder's work while the
# holder is still within its own TTL.
_WAIT_ATTEMPTS = 100
_FAILURE_MARKER_TTL_SECONDS = 2


def _failure_marker_key(lock_key: str) -> str:
    return f"{lock_key}:failed"


async def acquire_lock(cache: Cache, lock_key: str, ttl_ms: float = _LOCK_TTL_MS) -> str | None:
    return await cache.acquire_lock(lock_key, ttl_ms)


async def release_lock(cache: Cache, lock_key: str, token: str) -> None:
    await cache.release_lock(lock_key, token)


async def _release_lock_best_effort(cache: Cache, lock_key: str, token: str) -> None:
    try:
        await release_lock(cache, lock_key, token)
    except Exception as exc:
        _logger.warning('failed to release single-flight lock "%s": %s', lock_key, exc)


async def wait_for_result(
    check: Callable[[], Awaitable[T | None]],
    attempts: int = _WAIT_ATTEMPTS,
    interval_ms: float = _WAIT_INTERVAL_MS,
) -> T | None:
    for _ in range(attempts):
        await asyncio.sleep(interval_ms / 1000)
        value = await check()
        if value is not None:
            return value
    return None


@dataclass
class SingleFlightOptions:
    lock_ttl_ms: float | None = None
    wait_attempts: int | None = None
    wait_interval_ms: float | None = None


async def with_single_flight(
    cache: Cache,
    lock_key: str,
    do_work: Callable[[], Awaitable[T]],
    poll_for_cached: Callable[[], Awaitable[T | None]],
    opts: SingleFlightOptions | None = None,
) -> T:
    opts = opts or SingleFlightOptions()
    lock_ttl_ms = opts.lock_ttl_ms if opts.lock_ttl_ms is not None else _LOCK_TTL_MS
    lock_token = await acquire_lock(cache, lock_key, lock_ttl_ms)
    if lock_token is not None:
        try:
            result = await do_work()
        except (Exception, asyncio.CancelledError):
            # CancelledError is a BaseException, not Exception -- caught explicitly, or cleanup
            # gets skipped.
            try:
                await cache.set(_failure_marker_key(lock_key), "1", _FAILURE_MARKER_TTL_SECONDS)
            except Exception:
                pass
            await _release_lock_best_effort(cache, lock_key, lock_token)
            raise
        await _release_lock_best_effort(cache, lock_key, lock_token)
        return result

    attempts = opts.wait_attempts if opts.wait_attempts is not None else _WAIT_ATTEMPTS
    interval_ms = opts.wait_interval_ms if opts.wait_interval_ms is not None else _WAIT_INTERVAL_MS
    for _ in range(attempts):
        await asyncio.sleep(interval_ms / 1000)
        value = await poll_for_cached()
        if value is not None:
            return value
        if await cache.get(_failure_marker_key(lock_key)) is not None:
            break

    return await do_work()
