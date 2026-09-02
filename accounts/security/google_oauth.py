"""
accounts/security/google_oauth.py

"Sign in with Google" (OAuth 2.0 Authorization Code flow). This is plain
OAuth plumbing, not one of the 12 from-scratch crypto requirements, so it
uses `requests` for the HTTP calls to Google rather than reimplementing
TLS/HTTP from scratch (compare accounts/security/hashing.py or
crypto_core/asymmetric/rsa_scratch.py, which ARE from-scratch requirements).

Flow (see accounts/views.py::google_login_start / google_login_callback):
    1. google_login_start redirects the browser to authorization_url(state).
    2. Google redirects back to GOOGLE_OAUTH_REDIRECT_URI with ?code=...&state=...
    3. google_login_callback calls fetch_google_profile(code), which:
        a. POSTs the code to Google's token endpoint to get an id_token (JWT).
        b. Decodes the JWT payload and checks iss/aud/exp/email_verified
           itself (see _decode_id_token below for why signature
           verification is skipped).

Trust model / why no JWT signature verification:
    The id_token is fetched by THIS SERVER directly from Google's token
    endpoint over TLS, not handed to us by the browser. That's different
    from the (deprecated) implicit/client-side flow, where a token arrives
    via a browser redirect an attacker could tamper with, and signature
    verification is mandatory. Here, an attacker would have to compromise
    TLS to Google itself to forge the payload, so this project decodes and
    reads the JWT claims directly rather than pulling in a JWT/crypto
    library just to re-verify a signature Google's own channel already
    guarantees. Issuer/audience/expiry/email_verified are still checked
    explicitly below as sanity checks against misconfiguration, not as the
    security boundary.
"""

import base64
import json
import secrets
import time
from urllib.parse import urlencode

import requests
from django.conf import settings

_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_VALID_ISSUERS = ("accounts.google.com", "https://accounts.google.com")


class GoogleOAuthError(Exception):
    """Raised when the OAuth exchange or ID token validation fails."""


def is_configured() -> bool:
    return bool(
        settings.GOOGLE_OAUTH_CLIENT_ID
        and settings.GOOGLE_OAUTH_CLIENT_SECRET
        and settings.GOOGLE_OAUTH_REDIRECT_URI
    )


def new_state_token() -> str:
    """
    Random per-attempt token, stashed in the session and echoed back by
    Google via the `state` query param, so google_login_callback can reject
    a callback that didn't originate from this app's own redirect (CSRF on
    the OAuth flow).
    """
    return secrets.token_urlsafe(32)


def authorization_url(state: str) -> str:
    params = {
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    }
    return f"{_AUTH_ENDPOINT}?{urlencode(params)}"


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _decode_id_token(id_token: str) -> dict:
    """Decode (not cryptographically verify - see module docstring) the
    JWT payload and sanity-check issuer/audience/expiry/email_verified."""
    try:
        _header_b64, payload_b64, _sig_b64 = id_token.split(".")
        claims = json.loads(_b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError) as exc:
        raise GoogleOAuthError("Malformed ID token from Google.") from exc

    if claims.get("iss") not in _VALID_ISSUERS:
        raise GoogleOAuthError(f"Unexpected token issuer: {claims.get('iss')!r}")
    if claims.get("aud") != settings.GOOGLE_OAUTH_CLIENT_ID:
        raise GoogleOAuthError("ID token audience does not match our client ID.")
    if claims.get("exp", 0) < time.time():
        raise GoogleOAuthError("ID token is expired.")
    if not claims.get("email_verified", False):
        raise GoogleOAuthError("Google account email is not verified.")

    return claims


def fetch_google_profile(code: str) -> dict:
    """
    Exchange an authorization `code` for the signed-in user's profile.

    Returns {"sub", "email", "given_name", "family_name", "picture"}.
    Raises GoogleOAuthError on any failure (network, bad code, malformed/
    invalid token) - callers should catch this and show a login error
    rather than letting it propagate as a 500.
    """
    try:
        response = requests.post(
            _TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
                "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        raise GoogleOAuthError("Could not reach Google's token endpoint.") from exc

    if response.status_code != 200:
        raise GoogleOAuthError(f"Google token exchange failed ({response.status_code}): {response.text[:200]}")

    id_token = response.json().get("id_token")
    if not id_token:
        raise GoogleOAuthError("Google's token response did not include an ID token.")

    claims = _decode_id_token(id_token)
    return {
        "sub": claims.get("sub", ""),
        "email": claims.get("email", ""),
        "given_name": claims.get("given_name", ""),
        "family_name": claims.get("family_name", ""),
        "picture": claims.get("picture", ""),
    }


_PICTURE_EXTENSIONS = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}


def download_profile_picture(url: str):
    """
    Best-effort fetch of a Google profile photo (the "picture" claim from
    fetch_google_profile). Returns (raw_bytes, file_extension), or None on
    any failure - this is a nice-to-have, so callers should treat a None
    result as "skip it" and never let a failed download block account
    creation or login.
    """
    if not url:
        return None
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException:
        return None

    extension = _PICTURE_EXTENSIONS.get(response.headers.get("Content-Type", ""), "jpg")
    return response.content, extension
