from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class CacheSetManyEntry:
    key: str
    value: str
    ttl_seconds: float


class Cache(Protocol):
    async def get(self, key: str) -> str | None: ...

    async def set(self, key: str, value: str, ttl_seconds: float) -> None: ...

    async def set_many(self, entries: list[CacheSetManyEntry]) -> None: ...

    async def acquire_lock(self, key: str, ttl_ms: float) -> str | None: ...

    async def release_lock(self, key: str, token: str) -> None: ...
