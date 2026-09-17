import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# so `import server` does not depend on the cwd
os.environ.setdefault("TICKETDESK_DATA", str(Path(__file__).resolve().parent.parent / "data"))
os.environ.setdefault("TICKETDESK_LOG_LEVEL", "WARNING")

import auth  # noqa: E402
import server  # noqa: E402
from storage import TicketStore  # noqa: E402

ISSUER = "https://issuer.test/realms/ticketdesk"


@pytest.fixture(autouse=True)
def _reset_user():
    # stdio identity lives in a contextvar; don't let it leak between tests
    token = server._current_user.set(None)
    yield
    server._current_user.reset(token)


@pytest.fixture
def store(tmp_path):
    (tmp_path / "tickets").mkdir()
    (tmp_path / "attachments" / "T-1").mkdir(parents=True)
    ticket = {
        "id": "T-1",
        "subject": "VPN handshake fails",
        "owner": "alice",
        "groups": ["eng"],
        "status": "open",
        "attachments": ["notes.txt"],
        "comments": [{"author": "alice", "body": "reproduced on 7.4.1"}],
    }
    (tmp_path / "tickets" / "T-1.json").write_text(json.dumps(ticket), encoding="utf-8")
    (tmp_path / "attachments" / "T-1" / "notes.txt").write_text(
        "плановые заметки", encoding="utf-8"
    )
    (tmp_path / "secret.txt").write_text("SUPER_SECRET", encoding="utf-8")
    return TicketStore(tmp_path)


@pytest.fixture(scope="session")
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


@pytest.fixture
def mint(monkeypatch, keypair):
    """Wire verify_token to a local RSA key (no JWKS lookup) and return a token
    factory: mint(preferred_username="carol", groups=["/hr"])."""
    private_pem, public_pem = keypair
    monkeypatch.setattr(
        auth._jwks_client,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=public_pem),
    )
    monkeypatch.setattr(auth, "ISSUER", ISSUER)
    monkeypatch.setattr(auth, "AUDIENCE", None)

    def _mint(algorithm="RS256", key=private_pem, **over):
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
        return jwt.encode(claims, key, algorithm=algorithm)

    return _mint
