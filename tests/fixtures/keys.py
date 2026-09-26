import json
import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


@dataclass
class TestKeyPair:
    kid: str
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey
    jwk: dict[str, Any]


def generate_test_key_pair(kid: str) -> TestKeyPair:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwk["use"] = "sig"
    return TestKeyPair(kid=kid, public_key=public_key, private_key=private_key, jwk=jwk)


def sign_test_token(
    pair: TestKeyPair,
    *,
    claims: dict[str, Any] | None = None,
    audience: str = "test-service",
    expires_in_seconds: float = 300,
    kid: str | None = None,
    signing_key: rsa.RSAPrivateKey | None = None,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "iat": now,
        **(claims or {}),
        "aud": audience,
        "exp": now + int(expires_in_seconds),
    }
    return jwt.encode(
        payload,
        signing_key or pair.private_key,
        algorithm="RS256",
        headers={"kid": kid or pair.kid},
    )
