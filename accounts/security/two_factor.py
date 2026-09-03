import base64
import io
import os
from datetime import datetime, timezone as dt_timezone
from urllib.parse import quote

import qrcode
import qrcode.image.svg

from accounts.models import TwoFactorSettings
from crypto_core.encryption_service import EncryptionService
from crypto_core.mac.hmac_scratch import compute_mac

OTP_DIGITS = 6
TIME_STEP_SECONDS = 30
ALLOWED_WINDOW_DRIFT = 1
ALGORITHM = "SHA256"
ISSUER = "SecureShare"
_SECRET_BYTES = 20


def _new_base32_secret() -> str:
    return base64.b32encode(os.urandom(_SECRET_BYTES)).decode("ascii").rstrip("=")


def _decode_base32(secret: str) -> bytes:
    padded = secret + "=" * (-len(secret) % 8)
    return base64.b32decode(padded, casefold=True)


def _time_step(when: datetime = None) -> int:
    if when is None:
        when = datetime.now(dt_timezone.utc)
    return int(when.timestamp()) // TIME_STEP_SECONDS


def _totp_code(secret: str, counter: int) -> str:
    mac = compute_mac(counter.to_bytes(8, "big"), _decode_base32(secret))
    offset = mac[-1] & 0x0F
    truncated = (
        ((mac[offset] & 0x7F) << 24)
        | ((mac[offset + 1] & 0xFF) << 16)
        | ((mac[offset + 2] & 0xFF) << 8)
        | (mac[offset + 3] & 0xFF)
    )
    return str(truncated % (10 ** OTP_DIGITS)).zfill(OTP_DIGITS)


def _stored_secret(settings_row) -> str:
    if not settings_row.secret:
        return ""
    return EncryptionService.decrypt_profile_data(settings_row.user, settings_row.secret)


def begin_enrolment(user) -> str:
    settings_row, _ = TwoFactorSettings.objects.get_or_create(user=user)
    secret = _new_base32_secret()
    settings_row.secret = EncryptionService.encrypt_profile_data(user, secret)
    settings_row.is_enabled = False
    settings_row.method = TwoFactorSettings.Method.TOTP
    settings_row.save(update_fields=["secret", "is_enabled", "method", "updated_at"])
    return secret


def confirm_enrolment(user, submitted_code: str) -> bool:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    if settings_row is None or not settings_row.secret:
        return False
    if not verify_code(user, submitted_code):
        return False
    settings_row.is_enabled = True
    settings_row.save(update_fields=["is_enabled", "updated_at"])
    return True


def disable(user) -> None:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    if settings_row is None:
        return
    settings_row.is_enabled = False
    settings_row.secret = ""
    settings_row.save(update_fields=["is_enabled", "secret", "updated_at"])


def is_enrolling(user) -> bool:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    return bool(settings_row and settings_row.secret and not settings_row.is_enabled)


def is_required_for(user) -> bool:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    return bool(settings_row and settings_row.is_enabled and settings_row.secret)


def current_secret(user) -> str:
    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    return _stored_secret(settings_row) if settings_row else ""


def provisioning_uri(user, secret: str) -> str:
    label = quote(f"{ISSUER}:{user.username}")
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret}&issuer={quote(ISSUER)}"
        f"&algorithm={ALGORITHM}&digits={OTP_DIGITS}&period={TIME_STEP_SECONDS}"
    )


def qr_svg(uri: str) -> str:
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


def current_code(user) -> str:
    secret = current_secret(user)
    return _totp_code(secret, _time_step()) if secret else ""


def seconds_remaining() -> int:
    now = int(datetime.now(dt_timezone.utc).timestamp())
    return TIME_STEP_SECONDS - (now % TIME_STEP_SECONDS)


def verify_code(user, submitted_code: str) -> bool:
    submitted = (submitted_code or "").strip().replace(" ", "")
    if not submitted.isdigit() or len(submitted) != OTP_DIGITS:
        return False

    settings_row = TwoFactorSettings.objects.filter(user=user).first()
    if settings_row is None or not settings_row.secret:
        return False

    secret = _stored_secret(settings_row)
    step = _time_step()
    for drift in range(-ALLOWED_WINDOW_DRIFT, ALLOWED_WINDOW_DRIFT + 1):
        expected = _totp_code(secret, step + drift)
        if len(expected) == len(submitted) and _constant_time_equals(expected, submitted):
            return True
    return False


def _constant_time_equals(a: str, b: str) -> bool:
    diff = 0
    for x, y in zip(a.encode(), b.encode()):
        diff |= x ^ y
    return diff == 0
