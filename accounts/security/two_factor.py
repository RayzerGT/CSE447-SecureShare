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
_ALLOWED_WINDOW_DRIFT = 1

def _get_or_create_secret(user) -> str:
    settings_row, _ = TwoFactorSettings.objects.get_or_create(user=user)
    if not settings_row.secret:
        settings_row.secret = EncryptionService.encrypt_profile_data(user, secrets.token_hex(20))
        settings_row.save(update_fields=["secret"])
        return EncryptionService.decrypt_profile_data(user, settings_row.secret)

    try:
        return EncryptionService.decrypt_profile_data(user, settings_row.secret)
    except (ValueError, UnicodeDecodeError):
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
    counter_bytes = counter.to_bytes(8, "big")
    mac = compute_mac(counter_bytes, secret.encode("utf-8"))

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
    secret = _get_or_create_secret(user)
    code = _hotp_code(secret, _time_step())

    logger.info("2FA code for user '%s': %s (valid ~%ss)", user.username, code, _TIME_STEP_SECONDS)

    if settings.DEBUG:
        return code
    return ""

def verify_otp(user, submitted_code: str) -> bool:
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
