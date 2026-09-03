"""
accounts/security/two_factor.py

REQUIREMENT (CSE447 Project.pdf): "A verification function must enforce
two-step authentication, validating both primary credentials and a second
factor before granting access."

DESIGN CHOICE (documented, per todo.txt "your choice, document it"):
    TOTP - Time-based One-Time Password, per RFC 6238 - built entirely on
    top of this project's own from-scratch HMAC (crypto_core.mac.hmac_scratch,
    Munia's Task 1). No `pyotp`/`hashlib`/`hmac` shortcuts.

    - Each user's TwoFactorSettings.secret holds a random per-user secret
      (URL-safe base64 text), generated the first time an OTP is requested
      for them if they don't already have one.
    - `generate_otp` derives a 6-digit code from
      HMAC(secret, floor(unix_time / 30)) using crypto_core.mac.hmac_scratch,
      then truncates it down to 6 digits the standard RFC 4226 "dynamic
      truncation" way.
    - `verify_otp` recomputes the code for the CURRENT 30-second window and
      the window immediately before/after it (a small allowance for clock
      drift / the user being slow to type), and accepts a match against any
      of the three.
    - DELIVERY: this project has no configured email backend
      (secureshare/settings.py has no EMAIL_BACKEND wired to a real SMTP
      server), so instead of silently failing on send_mail, the generated
      code is written to the server log (so it's visible to whoever runs
      `runserver`) and, ONLY when settings.DEBUG is True, also handed back
      to accounts/views.py so it can be flashed on the verify-2FA page for
      local testing. It is never exposed when DEBUG is False.

TODO(Mos. Mahabuba Akter Munia) - still open:
    - Once crypto_core.encryption_service.encrypt_profile_data /
      decrypt_profile_data are usable (i.e. once Afnan's RSA is done), swap
      the plaintext `TwoFactorSettings.secret` for an encrypted-at-rest
      value: encrypt on first generation, decrypt right before computing the
      OTP. Left as plaintext-at-rest for now so 2FA is testable before RSA
      lands - tracked, not forgotten.
"""

import logging
import secrets
from datetime import datetime, timezone as dt_timezone

from django.conf import settings

from accounts.models import TwoFactorSettings
from crypto_core.mac.hmac_scratch import compute_mac
from crypto_core.encryption_service import EncryptionService

logger = logging.getLogger("accounts.security.two_factor")

_OTP_DIGITS = 6
_TIME_STEP_SECONDS = 30
_ALLOWED_WINDOW_DRIFT = 1  # accept the window before/after the current one


def _get_or_create_secret(user) -> str:
    """
    Every user needs a stable per-user secret to derive codes from. Created
    once, on first use, and reused after that (recreating it every call
    would make previously-sent codes invalid).
    """
    settings_row, _ = TwoFactorSettings.objects.get_or_create(user=user)
    if not settings_row.secret:
        # 20 random bytes, hex-encoded - plenty of entropy for an HMAC key.
        settings_row.secret = EncryptionService.encrypt_profile_data(user, secrets.token_hex(20))
        settings_row.save(update_fields=["secret"])
        return EncryptionService.decrypt_profile_data(user, settings_row.secret)

    try:
        return EncryptionService.decrypt_profile_data(user, settings_row.secret)
    except (ValueError, UnicodeDecodeError):
        # Migrate legacy development rows that stored the raw hex secret.
        if len(settings_row.secret) == 40:
            encrypted_secret = EncryptionService.encrypt_profile_data(user, settings_row.secret)
            settings_row.secret = encrypted_secret
            settings_row.save(update_fields=["secret"])
            return EncryptionService.decrypt_profile_data(user, encrypted_secret)
        raise ValueError("stored 2FA secret could not be decrypted")


def _time_step(when: datetime = None) -> int:
    if when is None:
        when = datetime.now(dt_timezone.utc)
    return int(when.timestamp()) // _TIME_STEP_SECONDS


def _hotp_code(secret: str, counter: int) -> str:
    """
    RFC 4226-style HOTP, but using our own from-scratch HMAC (SHA-256-based)
    instead of the RFC's HMAC-SHA1 - the truncation step is unaffected by
    that swap and works the same way.
    """
    counter_bytes = counter.to_bytes(8, "big")
    mac = compute_mac(counter_bytes, secret.encode("utf-8"))

    # Dynamic truncation (RFC 4226 section 5.3).
    offset = mac[-1] & 0x0F
    truncated = (
        ((mac[offset] & 0x7F) << 24)
        | ((mac[offset + 1] & 0xFF) << 16)
        | ((mac[offset + 2] & 0xFF) << 8)
        | (mac[offset + 3] & 0xFF)
    )
    code = truncated % (10 ** _OTP_DIGITS)
    return str(code).zfill(_OTP_DIGITS)


def generate_otp(user) -> str:
    """
    Generate (and "deliver") a fresh TOTP code for `user`. Returns the code
    itself so callers running in DEBUG can surface it for testing; in
    production (DEBUG=False) callers should NOT display the return value to
    the user - it's only logged server-side there.
    """
    secret = _get_or_create_secret(user)
    code = _hotp_code(secret, _time_step())

    logger.info("2FA code for user '%s': %s (valid ~%ss)", user.username, code, _TIME_STEP_SECONDS)

    if settings.DEBUG:
        # Local/dev convenience only - never reachable when DEBUG is False.
        return code
    return ""


def verify_otp(user, submitted_code: str) -> bool:
    """
    Check `submitted_code` against the current time window and the window
    immediately before/after it (clock drift / typing delay tolerance).
    """
    if not submitted_code or not submitted_code.isdigit():
        return False

    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    if not settings_row or not settings_row.secret:
        return False

    secret = _get_or_create_secret(user)
    current_step = _time_step()
    for drift in range(-_ALLOWED_WINDOW_DRIFT, _ALLOWED_WINDOW_DRIFT + 1):
        expected = _hotp_code(secret, current_step + drift)
        if secrets.compare_digest(expected, submitted_code):
            return True
    return False