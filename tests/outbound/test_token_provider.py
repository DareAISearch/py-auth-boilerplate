import base64
import json
import math
from dataclasses import dataclass, replace
from typing import Any

import httpx2 as httpx
import pytest

from py_auth_boilerplate.cache.memory_cache import InMemoryCache
from py_auth_boilerplate.errors import AuthConfigError, UpstreamError
from py_auth_boilerplate.outbound.token_provider import create_token_provider


@dataclass
class _Config:
    iam_service_url: str
    service_name: str
    client_id: str | None
    client_secret: str | None
    outbound_token_max_ttl_seconds: int
    outbound_token_safety_margin_seconds: int


_CONFIG = _Config(
    iam_service_url="https://iam.test.example.com",
    service_name="test-service",
    client_id="test-client-id",
    client_secret="test-secret",
    outbound_token_max_ttl_seconds=3600,
    outbound_token_safety_margin_seconds=30,
)


@dataclass
class _CapturedRequest:
    url: str
    headers: dict[str, str]
    body: str


class TestCreateTokenProvider:
    def setup_method(self) -> None:
        self.cache = InMemoryCache()
        self.mint_call_count = 0
        self.captured_requests: list[_CapturedRequest] = []
        self._next_response_body: dict[str, Any] | None = None
        self._next_status = 200

    def _default_body(self) -> dict[str, Any]:
        return {
            "access_token": f"token-for-call-{self.mint_call_count}",
            "token_type": "Bearer",
            "expires_in": 3600,
            "expires_at": 0,
        }

    def set_next_response(self, *, status: int = 200, body: dict[str, Any] | None = None) -> None:
        self._next_status = status
        self._next_response_body = body

    def _make_provider(self, config: _Config = _CONFIG):
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            self.mint_call_count += 1
            options = options or {}
            self.captured_requests.append(
                _CapturedRequest(
                    url=url,
                    headers=dict(options.get("headers") or {}),
                    body=options.get("content") or "",
                )
            )
            body = self._next_response_body if self._next_response_body is not None else self._default_body()
            content = json.dumps(body).encode() if self._next_status != 401 else b"unauthorized"
            return httpx.Response(self._next_status, content=content)

        return create_token_provider(config=config, cache=self.cache, fetch_impl=fetch_impl)

    async def test_mints_a_fresh_token_when_nothing_is_cached(self) -> None:
        provider = self._make_provider()
        token = await provider.get_token("llm-gateway-fresh")
        assert token == "token-for-call-1"

    async def test_posts_to_token_with_a_basic_auth_header(self) -> None:
        provider = self._make_provider()
        await provider.get_token("llm-gateway-headers-test")
        req = self.captured_requests[-1]
        assert req.url == "https://iam.test.example.com/token"
        auth_header = req.headers["Authorization"]
        assert auth_header.startswith("Basic ")
        decoded = base64.b64decode(auth_header.removeprefix("Basic ")).decode()
        assert decoded == "test-client-id:test-secret"

    async def test_sends_the_requested_aud_in_the_request_body(self) -> None:
        provider = self._make_provider()
        await provider.get_token("some-specific-audience")
        req = self.captured_requests[-1]
        assert json.loads(req.body)["aud"] == "some-specific-audience"

    async def test_sends_service_name_as_sub_automatically(self) -> None:
        provider = self._make_provider()
        await provider.get_token("some-specific-audience")
        req = self.captured_requests[-1]
        assert json.loads(req.body)["sub"] == "test-service"

    async def test_sends_custom_claims_nested_under_custom_claims_when_supplied(self) -> None:
        provider = self._make_provider()
        await provider.get_token(
            "llm-gateway-with-hook", {"webhook_url": "https://service.example.com/v1/webhooks/llm-gateway"}
        )
        req = self.captured_requests[-1]
        parsed = json.loads(req.body)
        assert parsed["custom_claims"] == {
            "webhook_url": "https://service.example.com/v1/webhooks/llm-gateway"
        }

    async def test_omits_custom_claims_entirely_when_not_supplied(self) -> None:
        provider = self._make_provider()
        await provider.get_token("some-caller-sub")
        req = self.captured_requests[-1]
        assert "custom_claims" not in json.loads(req.body)

    async def test_a_second_call_for_the_same_aud_is_served_from_cache_no_new_mint(self) -> None:
        provider = self._make_provider()
        before = self.mint_call_count
        first = await provider.get_token("cache-me")
        after_first = self.mint_call_count
        second = await provider.get_token("cache-me")
        assert after_first == before + 1
        assert self.mint_call_count == after_first
        assert first == second

    async def test_different_aud_values_get_independent_tokens(self) -> None:
        provider = self._make_provider()
        a = await provider.get_token("aud-a")
        b = await provider.get_token("aud-b")
        assert a != b

    async def test_different_custom_claims_for_the_same_aud_get_independent_tokens(self) -> None:
        provider = self._make_provider()
        before = self.mint_call_count
        with_a = await provider.get_token("shared-aud", {"webhook_url": "https://a.example.com/hook"})
        with_b = await provider.get_token("shared-aud", {"webhook_url": "https://b.example.com/hook"})
        assert with_a != with_b
        assert self.mint_call_count == before + 2

    async def test_same_custom_claims_content_shares_a_cache_entry_regardless_of_key_order(self) -> None:
        provider = self._make_provider()
        before = self.mint_call_count
        first = await provider.get_token("shared-aud-2", {"a": "1", "b": "2"})
        second = await provider.get_token("shared-aud-2", {"b": "2", "a": "1"})
        assert first == second
        assert self.mint_call_count == before + 1

    async def test_custom_claims_omitted_vs_explicit_empty_dict_cached_independently(self) -> None:
        provider = self._make_provider()
        before = self.mint_call_count
        await provider.get_token("shared-aud-3")
        await provider.get_token("shared-aud-3", {})
        assert self.mint_call_count == before + 2

    async def test_concurrent_get_token_calls_for_a_fresh_aud_trigger_exactly_one_mint(self) -> None:
        import asyncio

        provider = self._make_provider()
        results = await asyncio.gather(*(provider.get_token("concurrent-aud") for _ in range(8)))
        assert len(set(results)) == 1
        assert self.mint_call_count == 1

    async def test_raises_when_the_iam_service_responds_with_a_non_2xx_status(self) -> None:
        self.set_next_response(status=401)
        provider = self._make_provider()
        with pytest.raises(UpstreamError, match="IAM token mint failed"):
            await provider.get_token("will-fail")

    async def test_caches_for_iam_services_actual_expires_in_not_our_own_max_ttl(self) -> None:
        self.set_next_response(
            body={
                "access_token": "short-lived-token",
                "token_type": "Bearer",
                "expires_in": 5,
                "expires_at": 0,
            }
        )
        provider = self._make_provider()
        before = self.mint_call_count
        token = await provider.get_token("short-ttl-aud")
        assert token == "short-lived-token"
        # safety margin (30s) exceeds expires_in (5s), so ttl <= 0 -- must not be cached at all.
        await provider.get_token("short-ttl-aud")
        assert self.mint_call_count == before + 2

    async def test_raises_a_clear_error_when_access_token_is_missing_or_null(self) -> None:
        self.set_next_response(
            body={"access_token": None, "token_type": "Bearer", "expires_in": 3600, "expires_at": 0}
        )
        provider = self._make_provider()
        with pytest.raises(UpstreamError, match="malformed response.*access_token"):
            await provider.get_token("malformed-token-aud")

    async def test_raises_a_clear_error_when_expires_in_is_non_numeric(self) -> None:
        self.set_next_response(
            body={
                "access_token": "a-real-token",
                "token_type": "Bearer",
                "expires_in": "soon",
                "expires_at": 0,
            }
        )
        provider = self._make_provider()
        with pytest.raises(UpstreamError, match="malformed response.*expires_in"):
            await provider.get_token("bad-expires-aud")

    async def test_nan_and_none_in_the_same_custom_claims_position_do_not_collide(self) -> None:
        provider = self._make_provider()
        before = self.mint_call_count
        with_none = await provider.get_token("nan-null-aud", {"limit": None})
        with_nan = await provider.get_token("nan-null-aud", {"limit": math.nan})
        assert with_none != with_nan
        assert self.mint_call_count == before + 2

    async def test_raises_a_clear_upstream_error_when_the_iam_response_body_is_not_valid_json(self) -> None:
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            return httpx.Response(200, content=b"not-json{{")

        provider = create_token_provider(config=_CONFIG, cache=self.cache, fetch_impl=fetch_impl)
        with pytest.raises(UpstreamError, match="malformed response.*invalid JSON"):
            await provider.get_token("invalid-json-aud")

    async def test_raises_a_clear_value_error_for_custom_claims_nested_past_the_depth_cap(self) -> None:
        provider = self._make_provider()
        deeply_nested: dict[str, Any] = {"done": True}
        for _ in range(50):
            deeply_nested = {"nested": deeply_nested}
        with pytest.raises(ValueError, match="nested too deeply"):
            await provider.get_token("deep-claims-aud", deeply_nested)


class TestMissingOutboundCredentials:
    def _config_without_credentials(self) -> _Config:
        return replace(_CONFIG, client_id=None, client_secret=None)

    def _provider_without_credentials(self):
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            raise AssertionError("fetch_impl should never be called when outbound credentials are missing")

        return create_token_provider(
            config=self._config_without_credentials(), cache=InMemoryCache(), fetch_impl=fetch_impl
        )

    def test_create_token_provider_itself_does_not_raise(self) -> None:
        self._provider_without_credentials()

    async def test_get_token_raises_auth_config_error_naming_every_missing_field(self) -> None:
        provider = self._provider_without_credentials()
        with pytest.raises(AuthConfigError, match=r"(?s)clientId.*clientSecret"):
            await provider.get_token("some-aud")

    async def test_get_token_raises_even_for_an_aud_that_would_otherwise_be_a_cache_hit(self) -> None:
        cache = InMemoryCache()
        await cache.set("iam_token:already-cached-aud", "stale-token", 60)
        provider = create_token_provider(config=self._config_without_credentials(), cache=cache)
        with pytest.raises(AuthConfigError):
            await provider.get_token("already-cached-aud")

    async def test_naming_just_one_missing_field_still_raises_listing_only_what_is_missing(self) -> None:
        provider = create_token_provider(
            config=replace(_CONFIG, client_secret=None),
            cache=InMemoryCache(),
        )
        with pytest.raises(AuthConfigError) as exc_info:
            await provider.get_token("some-aud")
        message = str(exc_info.value)
        assert "clientSecret" in message
        assert "clientId (" not in message
