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
    pass

def is_configured() -> bool:
    return bool(
        settings.GOOGLE_OAUTH_CLIENT_ID
        and settings.GOOGLE_OAUTH_CLIENT_SECRET
        and settings.GOOGLE_OAUTH_REDIRECT_URI
    )

def new_state_token() -> str:
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
    if not url:
        return None
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException:
        return None

    extension = _PICTURE_EXTENSIONS.get(response.headers.get("Content-Type", ""), "jpg")
    return response.content, extension
