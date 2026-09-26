"""Self-contained, runnable demo of py-auth-boilerplate: no external IAM/JWKS server needed.
A single FastAPI app plays three roles at once - the IAM service, the resource server, and the
client minting its own outbound token.

Run with: python examples/fastapi_server/server.py
"""

import asyncio
import json
import time

import httpx2 as httpx
import jwt as pyjwt
import uvicorn
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from jwt.algorithms import RSAAlgorithm

from py_auth_boilerplate import UNSET, InMemoryCache, assert_claim_matches, create_token_provider
from py_auth_boilerplate.fastapi import create_auth_plugin

SERVICE_NAME = "example-service"
PORT = 3210
BASE_URL = f"http://127.0.0.1:{PORT}"


class _JwtVerifierConfig:
    def __init__(self) -> None:
        self.jwks_url = f"{BASE_URL}/.well-known/jwks.json"
        self.service_name = SERVICE_NAME
        self.jwks_cache_ttl_seconds = 900
        self.token_cache_max_ttl_seconds = 300
        self.clock_tolerance_seconds = 0


class _TokenProviderConfig:
    def __init__(self) -> None:
        self.iam_service_url = BASE_URL
        self.service_name = SERVICE_NAME
        self.client_id = "example-client"
        self.client_secret = "unused-in-this-demo"
        self.outbound_token_max_ttl_seconds = 3600
        self.outbound_token_safety_margin_seconds = 30


async def main() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = "demo-kid"
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"

    app = FastAPI()
    cache = InMemoryCache()

    @app.get("/.well-known/jwks.json")
    async def jwks() -> dict:
        return {"keys": [jwk]}

    @app.post("/token")
    async def mint_token(request: Request) -> JSONResponse:
        body = await request.json()
        now = int(time.time())
        payload = {
            **(body.get("custom_claims") or {}),
            "sub": body.get("sub"),
            "iat": now,
            "aud": body["aud"],
            "exp": now + 3600,
        }
        access_token = pyjwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "demo-kid"})
        # RFC 6749 §5.1: token responses must not be cached.
        return JSONResponse(
            {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600, "expires_at": 0},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    plugin = create_auth_plugin(app=app, config=_JwtVerifierConfig(), cache=cache)

    @app.post("/protected")
    async def protected(request: Request, identity: dict = Depends(plugin.require_auth)) -> dict:
        body = await request.json()
        assert_claim_matches(identity, "webhook_url", body.get("webhook_url", UNSET))
        return {"sub": identity.get("sub"), "aud": identity.get("aud")}

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=PORT, log_level="warning"))
    server_task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    print(f"Demo server listening on {BASE_URL}")

    try:
        provider = create_token_provider(config=_TokenProviderConfig(), cache=cache)

        webhook_url = "https://example.com/webhooks/demo"
        access_token = await provider.get_token(SERVICE_NAME, {"webhook_url": webhook_url})
        print(f"Minted outbound token for aud={SERVICE_NAME}")

        async with httpx.AsyncClient() as client:
            ok = await client.post(
                f"{BASE_URL}/protected",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"webhook_url": webhook_url},
            )
            print("Matching webhook_url -> status", ok.status_code, ok.json())

            mismatch = await client.post(
                f"{BASE_URL}/protected",
                headers={"Authorization": f"Bearer {access_token}"},
                json={"webhook_url": "https://someone-else.example.com/hook"},
            )
            print("Mismatched webhook_url -> status", mismatch.status_code)

            no_auth = await client.post(f"{BASE_URL}/protected", json={})
            print("Missing Authorization header -> status", no_auth.status_code)
    finally:
        server.should_exit = True
        await server_task


if __name__ == "__main__":
    asyncio.run(main())
