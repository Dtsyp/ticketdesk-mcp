import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import auth

ISSUER = "https://issuer.test/realms/ticketdesk"


@pytest.fixture(scope="module")
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture(autouse=True)
def _wire_auth(monkeypatch, keypair):
    _, public_pem = keypair
    # Skip the network JWKS lookup; hand verify_token our public key directly.
    monkeypatch.setattr(
        auth._jwks_client,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=public_pem),
    )
    monkeypatch.setattr(auth, "ISSUER", ISSUER)
    monkeypatch.setattr(auth, "AUDIENCE", None)


def _claims(**over):
    now = int(time.time())
    claims = {
        "preferred_username": "alice",
        "iss": ISSUER,
        "iat": now,
        "exp": now + 300,
        "realm_access": {"roles": ["employee"]},
        "groups": ["/eng"],
        "scope": "tickets:read",
    }
    claims.update(over)
    return claims


def test_valid_token(keypair):
    private_pem, _ = keypair
    token = jwt.encode(_claims(), private_pem, algorithm="RS256")
    user = auth.verify_token(token)
    assert user["username"] == "alice"
    assert user["groups"] == ["eng"]
    assert "tickets:read" in user["scopes"]


def test_expired_token_rejected(keypair):
    private_pem, _ = keypair
    token = jwt.encode(_claims(exp=int(time.time()) - 3600),
                       private_pem, algorithm="RS256")
    with pytest.raises(auth.AuthError):
        auth.verify_token(token)


def test_wrong_issuer_rejected(keypair):
    private_pem, _ = keypair
    token = jwt.encode(_claims(iss="https://evil.example"),
                       private_pem, algorithm="RS256")
    with pytest.raises(auth.AuthError):
        auth.verify_token(token)


def test_hs256_token_rejected():
    # Algorithm-confusion defence: an HS256 token must be refused outright,
    # because only RS256 is accepted. (The classic attack reuses the JWKS public
    # key as the HMAC secret; restricting the algorithm kills the whole class.)
    forged = jwt.encode(_claims(), "public-key-as-hmac-secret", algorithm="HS256")
    with pytest.raises(auth.AuthError):
        auth.verify_token(forged)
