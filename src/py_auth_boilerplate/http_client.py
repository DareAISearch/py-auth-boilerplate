from collections.abc import Awaitable, Callable
from typing import TypedDict

import httpx2 as httpx

DEFAULT_TIMEOUT_SECONDS = 10.0


class HttpClientOptions(TypedDict, total=False):
    method: str
    headers: dict[str, str]
    content: bytes | str
    timeout_seconds: float
    follow_redirects: bool


FetchImpl = Callable[..., Awaitable[httpx.Response]]


async def http_fetch(url: str, options: HttpClientOptions | None = None) -> httpx.Response:
    opts: HttpClientOptions = options or {}
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT_SECONDS, follow_redirects=False) as client:
        return await client.request(
            opts.get("method", "GET"),
            url,
            headers=opts.get("headers"),
            content=opts.get("content"),
            timeout=opts.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS),
            follow_redirects=opts.get("follow_redirects", False),
        )
