import time

import pytest

import auth


def test_valid_token(mint):
    user = auth.verify_token(mint())
    assert user["username"] == "alice"
    assert user["groups"] == ["eng"]
    assert "tickets:read" in user["scopes"]


def test_expired_token_rejected(mint):
    with pytest.raises(auth.AuthError):
        auth.verify_token(mint(exp=int(time.time()) - 3600))


def test_wrong_issuer_rejected(mint):
    with pytest.raises(auth.AuthError):
        auth.verify_token(mint(iss="https://evil.example"))


def test_hs256_token_rejected(mint):
    # Algorithm-confusion defence: an HS256 token must be refused outright,
    # because only RS256 is accepted. (The classic attack reuses the JWKS public
    # key as the HMAC secret; restricting the algorithm kills the whole class.)
    forged = mint(algorithm="HS256", key="public-key-as-hmac-secret")
    with pytest.raises(auth.AuthError):
        auth.verify_token(forged)


def test_audience_checked_when_configured(mint, monkeypatch):
    monkeypatch.setattr(auth, "AUDIENCE", "ticketdesk-mcp")
    assert auth.verify_token(mint(aud="ticketdesk-mcp"))["username"] == "alice"
    with pytest.raises(auth.AuthError):
        auth.verify_token(mint())  # no aud at all
    with pytest.raises(auth.AuthError):
        auth.verify_token(mint(aud="account"))  # what Keycloak emits without a mapper
