import asyncio
import json
import time
from dataclasses import dataclass, replace

import httpx2 as httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from py_auth_boilerplate.cache.memory_cache import InMemoryCache
from py_auth_boilerplate.errors import AuthError, JwksUnavailableError
from py_auth_boilerplate.jwt.jwt_verifier import create_jwt_verifier

from ..fixtures.keys import generate_test_key_pair, sign_test_token

_JWKS_URL = "https://iam.test.example.com/.well-known/jwks.json"
_AUDIENCE = "test-service"


@dataclass
class _Config:
    jwks_url: str
    service_name: str
    jwks_cache_ttl_seconds: int
    token_cache_max_ttl_seconds: int
    clock_tolerance_seconds: int


def _base_config(**overrides: object) -> _Config:
    config = _Config(
        jwks_url=_JWKS_URL,
        service_name=_AUDIENCE,
        jwks_cache_ttl_seconds=604_800,
        token_cache_max_ttl_seconds=300,
        clock_tolerance_seconds=0,
    )
    return replace(config, **overrides) if overrides else config


def _jwks_response(*jwks: dict, cache_control: str | None = None) -> httpx.Response:
    headers = {"content-type": "application/json"}
    if cache_control is not None:
        headers["cache-control"] = cache_control
    return httpx.Response(200, content=json.dumps({"keys": list(jwks)}).encode(), headers=headers)


class TestCreateJwtVerifier:
    def setup_method(self) -> None:
        self.cache = InMemoryCache()
        self.fetch_count = 0
        self.key_pair_a = generate_test_key_pair("kid-a")
        self.key_pair_b = generate_test_key_pair("kid-b")

    def _make_verifier(self, *, clock_tolerance_seconds: int = 0, jwks_cache_ttl_seconds: int = 604_800):
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            self.fetch_count += 1
            if url != _JWKS_URL:
                return httpx.Response(404, content=b"not found")
            return _jwks_response(self.key_pair_a.jwk, self.key_pair_b.jwk)

        return create_jwt_verifier(
            config=_base_config(
                clock_tolerance_seconds=clock_tolerance_seconds,
                jwks_cache_ttl_seconds=jwks_cache_ttl_seconds,
            ),
            cache=self.cache,
            fetch_impl=fetch_impl,
        )

    async def test_verifies_a_validly_signed_token_and_returns_its_claims(self) -> None:
        verifier = self._make_verifier()
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "some-client"})
        claims = await verifier.verify(token)
        assert claims["sub"] == "some-client"
        assert claims["aud"] == _AUDIENCE

    async def test_second_verification_of_same_token_hits_the_cache_no_new_jwks_fetch(self) -> None:
        verifier = self._make_verifier()
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "cache-test"})
        await verifier.verify(token)
        after_first = self.fetch_count
        await verifier.verify(token)
        assert self.fetch_count == after_first

    async def test_two_distinct_tokens_sharing_a_kid_both_verify_via_the_same_cached_jwks_document(
        self,
    ) -> None:
        verifier = self._make_verifier()
        token_a = sign_test_token(self.key_pair_b, audience=_AUDIENCE, claims={"sub": "a"})
        token_b = sign_test_token(self.key_pair_b, audience=_AUDIENCE, claims={"sub": "b"})
        assert (await verifier.verify(token_a))["sub"] == "a"
        assert (await verifier.verify(token_b))["sub"] == "b"
        assert self.fetch_count == 1

    async def test_rejects_a_token_signed_for_the_wrong_audience(self) -> None:
        verifier = self._make_verifier()
        token = sign_test_token(self.key_pair_a, audience="some-other-service", claims={"sub": "x"})
        with pytest.raises(AuthError):
            await verifier.verify(token)

    async def test_rejects_a_token_with_an_unknown_kid(self) -> None:
        verifier = self._make_verifier()
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, kid="unknown-kid-not-in-jwks")
        with pytest.raises(AuthError, match="unknown kid"):
            await verifier.verify(token)

    async def test_rejects_a_malformed_token(self) -> None:
        verifier = self._make_verifier()
        with pytest.raises(AuthError):
            await verifier.verify("not-a-real-jwt")

    async def test_rejects_an_expired_token(self) -> None:
        verifier = self._make_verifier()
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, expires_in_seconds=-1)
        with pytest.raises(AuthError):
            await verifier.verify(token)

    async def test_rejects_a_token_signed_with_a_key_that_does_not_match_its_claimed_kid(self) -> None:
        verifier = self._make_verifier()
        other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        now = int(time.time())
        token = pyjwt.encode(
            {"sub": "x", "iat": now, "aud": _AUDIENCE, "exp": now + 300},
            other_private_key,
            algorithm="RS256",
            headers={"kid": self.key_pair_a.kid},
        )
        with pytest.raises(AuthError):
            await verifier.verify(token)

    async def test_jwks_cache_miss_under_concurrent_verifies_for_a_fresh_kid_triggers_one_fetch(self) -> None:
        verifier = self._make_verifier()
        tokens = [
            sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": f"c{i}"}) for i in range(8)
        ]
        await asyncio.gather(*(verifier.verify(t) for t in tokens))
        assert self.fetch_count == 1

    async def test_rejects_a_token_expired_by_2s_when_clock_tolerance_is_0_default(self) -> None:
        verifier = self._make_verifier(clock_tolerance_seconds=0)
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, expires_in_seconds=-2)
        with pytest.raises(AuthError):
            await verifier.verify(token)

    async def test_accepts_a_token_expired_by_2s_when_clock_tolerance_raised_to_5(self) -> None:
        verifier = self._make_verifier(clock_tolerance_seconds=5)
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, expires_in_seconds=-2)
        claims = await verifier.verify(token)
        assert claims["aud"] == _AUDIENCE

    async def test_two_verifiers_with_different_service_names_sharing_one_cache_do_not_cross_accept(
        self,
    ) -> None:
        other_audience = "other-service"

        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            return _jwks_response(self.key_pair_a.jwk)

        verifier_a = create_jwt_verifier(
            config=_base_config(service_name=_AUDIENCE), cache=self.cache, fetch_impl=fetch_impl
        )
        verifier_b = create_jwt_verifier(
            config=_base_config(service_name=other_audience),
            cache=self.cache,  # deliberately the same Cache instance as verifier_a
            fetch_impl=fetch_impl,
        )

        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "client-1"})
        claims = await verifier_a.verify(token)
        assert claims["aud"] == _AUDIENCE

        # Same shared cache, but verifier_b requires a different audience -- must re-verify
        # (and reject), not reuse verifier_a's cached verdict.
        with pytest.raises(AuthError):
            await verifier_b.verify(token)

    async def test_jwks_cache_miss_for_different_fresh_kids_still_triggers_only_one_fetch(self) -> None:
        verifier = self._make_verifier()
        token_a = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "a"})
        token_b = sign_test_token(self.key_pair_b, audience=_AUDIENCE, claims={"sub": "b"})
        await asyncio.gather(verifier.verify(token_a), verifier.verify(token_b))
        assert self.fetch_count == 1

    async def test_second_request_for_a_still_unknown_kid_does_not_retrigger_a_jwks_fetch(self) -> None:
        verifier = self._make_verifier()
        token1 = sign_test_token(self.key_pair_a, audience=_AUDIENCE, kid="totally-unknown-kid")
        with pytest.raises(AuthError):
            await verifier.verify(token1)
        after_first = self.fetch_count

        token2 = sign_test_token(self.key_pair_a, audience=_AUDIENCE, kid="totally-unknown-kid")
        with pytest.raises(AuthError):
            await verifier.verify(token2)
        assert self.fetch_count == after_first

    async def test_a_kid_added_after_the_jwks_document_was_cached_is_rejected_until_cache_expires(
        self,
    ) -> None:
        # A key rotated in mid-window is rejected until the cached document's own TTL lapses --
        # deliberate: an unknown kid is never retried against a fresh fetch.
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            self.fetch_count += 1
            return _jwks_response(self.key_pair_a.jwk)

        verifier = create_jwt_verifier(config=_base_config(), cache=self.cache, fetch_impl=fetch_impl)

        warming_token = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "warm"})
        await verifier.verify(warming_token)
        after_warm = self.fetch_count

        token = sign_test_token(self.key_pair_b, audience=_AUDIENCE, claims={"sub": "rotated-in"})
        with pytest.raises(AuthError, match="unknown kid"):
            await verifier.verify(token)
        assert self.fetch_count == after_warm

    async def test_raises_a_clear_jwks_unavailable_error_when_the_jwks_response_is_missing_a_keys_array(
        self,
    ) -> None:
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            return httpx.Response(200, content=b"{}", headers={"content-type": "application/json"})

        verifier = create_jwt_verifier(config=_base_config(), cache=InMemoryCache(), fetch_impl=fetch_impl)
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE)

        with pytest.raises(JwksUnavailableError, match="keys array"):
            await verifier.verify(token)

    async def test_raises_a_jwks_unavailable_error_not_an_auth_error_when_jwks_endpoint_returns_non_2xx(
        self,
    ) -> None:
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            return httpx.Response(503, content=b"service unavailable")

        verifier = create_jwt_verifier(config=_base_config(), cache=InMemoryCache(), fetch_impl=fetch_impl)
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE)

        with pytest.raises(JwksUnavailableError):
            await verifier.verify(token)
        try:
            await verifier.verify(token)
        except JwksUnavailableError as exc:
            assert not isinstance(exc, AuthError)

    async def test_a_concurrent_verify_for_a_different_genuinely_unknown_kid_resolves_promptly(self) -> None:
        # fetch_impl yields via a real asyncio.sleep: Python coroutines are lazy, so without a
        # genuine suspension point asyncio.gather can run one task to completion before the other
        # starts, which would make both verify() calls "win" an already-free lock instead of
        # exercising the winner/loser path this test targets.
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            self.fetch_count += 1
            await asyncio.sleep(0.05)
            return _jwks_response(self.key_pair_a.jwk, self.key_pair_b.jwk)

        verifier = create_jwt_verifier(config=_base_config(), cache=self.cache, fetch_impl=fetch_impl)
        token1 = sign_test_token(self.key_pair_a, audience=_AUDIENCE, kid="unknown-kid-one")
        token2 = sign_test_token(self.key_pair_a, audience=_AUDIENCE, kid="unknown-kid-two")

        start = time.monotonic()
        results = await asyncio.gather(
            verifier.verify(token1), verifier.verify(token2), return_exceptions=True
        )
        elapsed = time.monotonic() - start

        assert all(isinstance(r, AuthError) for r in results)
        assert self.fetch_count == 1
        assert elapsed < 5.0

    async def test_uses_cache_control_max_age_as_the_jwks_cache_ttl_refetching_once_it_lapses(self) -> None:
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            self.fetch_count += 1
            return _jwks_response(self.key_pair_a.jwk, cache_control="public, max-age=1")

        verifier = create_jwt_verifier(config=_base_config(), cache=self.cache, fetch_impl=fetch_impl)

        token_before_expiry = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "first"})
        await verifier.verify(token_before_expiry)
        assert self.fetch_count == 1

        await asyncio.sleep(1.1)

        token_after_expiry = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "second"})
        await verifier.verify(token_after_expiry)
        assert self.fetch_count == 2

    async def test_falls_back_to_jwks_cache_ttl_seconds_when_no_cache_control_header(self) -> None:
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            self.fetch_count += 1
            return _jwks_response(self.key_pair_a.jwk)

        verifier = create_jwt_verifier(
            config=_base_config(jwks_cache_ttl_seconds=1), cache=self.cache, fetch_impl=fetch_impl
        )

        token_before_expiry = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "first"})
        await verifier.verify(token_before_expiry)
        assert self.fetch_count == 1

        await asyncio.sleep(1.1)

        token_after_expiry = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "second"})
        await verifier.verify(token_after_expiry)
        assert self.fetch_count == 2

    async def test_falls_back_to_jwks_cache_ttl_seconds_when_max_age_has_trailing_garbage(self) -> None:
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            self.fetch_count += 1
            return _jwks_response(self.key_pair_a.jwk, cache_control="public, max-age=604800abc")

        verifier = create_jwt_verifier(
            config=_base_config(jwks_cache_ttl_seconds=1), cache=self.cache, fetch_impl=fetch_impl
        )

        token_before_expiry = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "first"})
        await verifier.verify(token_before_expiry)
        assert self.fetch_count == 1

        await asyncio.sleep(1.1)

        token_after_expiry = sign_test_token(self.key_pair_a, audience=_AUDIENCE, claims={"sub": "second"})
        await verifier.verify(token_after_expiry)
        assert self.fetch_count == 2

    async def test_raises_a_clear_jwks_unavailable_error_when_the_jwks_response_body_is_not_valid_json(
        self,
    ) -> None:
        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            return httpx.Response(200, content=b"not-json{{", headers={"content-type": "application/json"})

        verifier = create_jwt_verifier(config=_base_config(), cache=InMemoryCache(), fetch_impl=fetch_impl)
        token = sign_test_token(self.key_pair_a, audience=_AUDIENCE)

        with pytest.raises(JwksUnavailableError, match="keys array"):
            await verifier.verify(token)
