import json
from dataclasses import dataclass

import httpx2 as httpx
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from py_auth_boilerplate.cache.memory_cache import InMemoryCache
from py_auth_boilerplate.claims import UNSET, assert_claim_matches
from py_auth_boilerplate.fastapi.auth_plugin import create_auth_plugin

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


class TestCreateAuthPlugin:
    def setup_method(self) -> None:
        self.cache = InMemoryCache()
        self.key_pair = generate_test_key_pair("kid-a")
        self.cache_get_should_throw = False

        real_get = self.cache.get

        async def patched_get(key: str) -> str | None:
            if self.cache_get_should_throw:
                raise RuntimeError("cache backend unreachable")
            return await real_get(key)

        self.cache.get = patched_get  # type: ignore[method-assign]

        async def fetch_impl(url: str, options: dict | None = None) -> httpx.Response:
            if url != _JWKS_URL:
                return httpx.Response(404, content=b"not found")
            return httpx.Response(200, content=json.dumps({"keys": [self.key_pair.jwk]}).encode())

        app = FastAPI()

        plugin = create_auth_plugin(
            app=app,
            config=_Config(
                jwks_url=_JWKS_URL,
                service_name=_AUDIENCE,
                jwks_cache_ttl_seconds=604_800,
                token_cache_max_ttl_seconds=300,
                clock_tolerance_seconds=0,
            ),
            cache=self.cache,
            fetch_impl=fetch_impl,
        )

        @app.post("/protected")
        async def protected(request: Request, identity: dict = Depends(plugin.require_auth)) -> dict:
            body = await request.json()
            assert_claim_matches(identity, "webhook_url", body.get("webhook_url", UNSET))
            return {"sub": identity.get("sub")}

        # raise_server_exceptions=False so an uncaught 500 comes back as a response, not a raise.
        self.client = TestClient(app, raise_server_exceptions=False)

    def test_rejects_a_request_with_no_authorization_header(self) -> None:
        res = self.client.post("/protected", json={})
        assert res.status_code == 401
        assert res.json() == {"error": "unauthorized", "message": "missing bearer token"}

    def test_rejects_a_malformed_authorization_header(self) -> None:
        res = self.client.post("/protected", json={}, headers={"authorization": "Token abc"})
        assert res.status_code == 401
        assert res.json() == {"error": "unauthorized", "message": "missing bearer token"}

    def test_accepts_a_valid_token_and_populates_identity(self) -> None:
        token = sign_test_token(self.key_pair, audience=_AUDIENCE, claims={"sub": "client-1"})
        res = self.client.post("/protected", json={}, headers={"authorization": f"Bearer {token}"})
        assert res.status_code == 200
        assert res.json() == {"sub": "client-1"}

    def test_rejects_an_invalid_token_401_not_a_500(self) -> None:
        res = self.client.post("/protected", json={}, headers={"authorization": "Bearer not-a-real-jwt"})
        assert res.status_code == 401
        assert res.json() == {"error": "unauthorized", "message": "Missing or invalid bearer token"}

    def test_propagates_a_non_autherror_failure_as_a_500_not_a_false_401(self) -> None:
        self.cache_get_should_throw = True
        token = sign_test_token(self.key_pair, audience=_AUDIENCE, claims={"sub": "client-1"})
        res = self.client.post("/protected", json={}, headers={"authorization": f"Bearer {token}"})
        assert res.status_code == 500

    def test_rejects_when_body_webhook_url_does_not_match_the_caller_identity_claim(self) -> None:
        token = sign_test_token(
            self.key_pair,
            audience=_AUDIENCE,
            claims={"sub": "client-1", "webhook_url": "https://caller.example.com/hook"},
        )
        res = self.client.post(
            "/protected",
            json={"webhook_url": "https://someone-else.example.com/hook"},
            headers={"authorization": f"Bearer {token}"},
        )
        assert res.status_code == 403

    def test_accepts_when_body_webhook_url_matches_the_caller_identity_claim(self) -> None:
        token = sign_test_token(
            self.key_pair,
            audience=_AUDIENCE,
            claims={"sub": "client-1", "webhook_url": "https://caller.example.com/hook"},
        )
        res = self.client.post(
            "/protected",
            json={"webhook_url": "https://caller.example.com/hook"},
            headers={"authorization": f"Bearer {token}"},
        )
        assert res.status_code == 200
