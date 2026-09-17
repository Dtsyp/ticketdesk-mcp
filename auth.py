import logging
import os

import jwt
from jwt import InvalidTokenError, PyJWKClient
from jwt.exceptions import PyJWKClientError

logger = logging.getLogger(__name__)

JWKS_URL = os.environ.get(
    "TICKETDESK_JWKS_URL",
    "http://keycloak:8080/realms/ticketdesk/protocol/openid-connect/certs",
)
ISSUER = os.environ.get(
    "TICKETDESK_ISSUER",
    "http://keycloak:8080/realms/ticketdesk",
)
# Audience the resource server expects in `aud`. Keycloak fills it from the
# client / configured audience mapper. Without this check a token minted for a
# different service is happily accepted here (confused deputy).
AUDIENCE = os.environ.get("TICKETDESK_AUDIENCE") or None

# Only asymmetric signatures. Listing HS256 next to RS256 is the textbook
# algorithm-confusion hole: the RSA public key from JWKS doubles as an HMAC
# secret, so anyone who can read the (public) key can forge a valid token.
ALGORITHMS = ["RS256"]

# Tolerate a bit of clock drift between nodes instead of switching exp/nbf off.
LEEWAY = int(os.environ.get("TICKETDESK_JWT_LEEWAY", "60"))

_jwks_client = PyJWKClient(JWKS_URL, cache_keys=True)

if AUDIENCE is None:
    logger.warning(
        "TICKETDESK_AUDIENCE is not set - audience is not validated; "
        "set it in any real deployment"
    )


class AuthError(Exception):
    """Bearer token could not be trusted."""


def verify_token(token: str) -> dict:
    try:
        signing_key = _jwks_client.get_signing_key_from_jwt(token)
    except (PyJWKClientError, InvalidTokenError) as e:
        raise AuthError(f"cannot resolve signing key: {e}") from e

    try:
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALGORITHMS,
            issuer=ISSUER,
            audience=AUDIENCE,
            leeway=LEEWAY,
            options={
                "require": ["exp", "iat", "iss"],
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iss": True,
                "verify_aud": AUDIENCE is not None,
            },
        )
    except InvalidTokenError as e:
        raise AuthError(str(e)) from e

    return {
        "username": payload.get("preferred_username", "anonymous"),
        "groups": [g.lstrip("/") for g in payload.get("groups", [])],
        "roles": payload.get("realm_access", {}).get("roles", []),
        "scopes": payload.get("scope", "").split(),
    }
