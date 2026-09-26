import math
import uuid
from typing import Any

from redis.asyncio import Redis

from .types import CacheSetManyEntry


def _to_redis_ttl_seconds(ttl_seconds: float) -> int:
    return max(1, math.ceil(ttl_seconds))


# Compare-and-delete: only removes the lock if it still holds our token, so a lock that already
# expired and was re-acquired by someone else is never deleted out from under them.
_RELEASE_SCRIPT = """
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
"""


class RedisCache:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> "RedisCache":
        kwargs.setdefault("decode_responses", True)
        return cls(Redis.from_url(url, **kwargs))

    async def get(self, key: str) -> str | None:
        # A redis.asyncio.Redis client passed in directly (not via from_url) may not have
        # decode_responses=True, in which case this returns bytes -- decode defensively so the
        # Cache protocol's `str` contract holds regardless of how the client was constructed.
        value = await self._redis.get(key)
        return value.decode("utf-8") if isinstance(value, bytes) else value

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be positive, got {ttl_seconds}")
        await self._redis.set(key, value, ex=_to_redis_ttl_seconds(ttl_seconds))

    async def set_many(self, entries: list[CacheSetManyEntry]) -> None:
        if not entries:
            return
        for entry in entries:
            if entry.ttl_seconds <= 0:
                raise ValueError(
                    f'ttl_seconds must be positive, got {entry.ttl_seconds} for key "{entry.key}"'
                )

        pipeline = self._redis.pipeline()
        for entry in entries:
            pipeline.set(entry.key, entry.value, ex=_to_redis_ttl_seconds(entry.ttl_seconds))
        # raise_on_error=False so a partial failure (one bad SET) is inspected as a result list
        # instead of silently looking like a complete success.
        results = await pipeline.execute(raise_on_error=False)
        failed = next((result for result in results if isinstance(result, Exception)), None)
        if failed is not None:
            raise RuntimeError(f"RedisCache.set_many: pipeline command failed: {failed}")

    async def acquire_lock(self, key: str, ttl_ms: float) -> str | None:
        token = str(uuid.uuid4())
        if ttl_ms != int(ttl_ms):
            raise ValueError(f"ttl_ms must be a whole number of milliseconds, got {ttl_ms}")
        acquired = await self._redis.set(key, token, px=int(ttl_ms), nx=True)
        return token if acquired else None

    async def release_lock(self, key: str, token: str) -> None:
        await self._redis.eval(_RELEASE_SCRIPT, 1, key, token)

    async def aclose(self) -> None:
        await self._redis.aclose()
