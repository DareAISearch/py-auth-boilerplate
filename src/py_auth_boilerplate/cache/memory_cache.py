import time
import uuid
from dataclasses import dataclass

from .types import CacheSetManyEntry


@dataclass
class _Entry:
    value: str
    expires_at: float


class InMemoryCache:
    """In-process Cache for tests and single-instance use. Not cross-process: running more than
    one replica against InMemoryCache silently loses the stampede-protection benefit."""

    def __init__(self) -> None:
        self._store: dict[str, _Entry] = {}

    @property
    def size(self) -> int:
        return len(self._store)

    def _is_live(self, key: str) -> bool:
        entry = self._store.get(key)
        return entry is not None and entry.expires_at > time.monotonic()

    def _sweep_expired(self) -> None:
        now = time.monotonic()
        for key in [k for k, entry in self._store.items() if entry.expires_at <= now]:
            del self._store[key]

    async def get(self, key: str) -> str | None:
        return self._store[key].value if self._is_live(key) else None

    async def set(self, key: str, value: str, ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be positive, got {ttl_seconds}")
        self._sweep_expired()
        self._store[key] = _Entry(value, time.monotonic() + ttl_seconds)

    async def set_many(self, entries: list[CacheSetManyEntry]) -> None:
        for entry in entries:
            if entry.ttl_seconds <= 0:
                raise ValueError(
                    f'ttl_seconds must be positive, got {entry.ttl_seconds} for key "{entry.key}"'
                )
        self._sweep_expired()
        for entry in entries:
            self._store[entry.key] = _Entry(entry.value, time.monotonic() + entry.ttl_seconds)

    async def acquire_lock(self, key: str, ttl_ms: float) -> str | None:
        if self._is_live(key):
            return None
        token = str(uuid.uuid4())
        self._store[key] = _Entry(token, time.monotonic() + ttl_ms / 1000)
        return token

    async def release_lock(self, key: str, token: str) -> None:
        entry = self._store.get(key)
        if entry is not None and entry.value == token:
            del self._store[key]
