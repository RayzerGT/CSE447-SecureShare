"""
accounts/security/two_factor.py

REQUIREMENT (CSE447 Project.pdf): "A verification function must enforce
two-step authentication, validating both primary credentials and a second
factor before granting access." (Idea.pdf suggests TOTP or email-based OTP.)

TODO(Mos. Mahabuba Akter Munia):
    1. Implement OTP generation (TOTP per RFC 6238, or a random email OTP
       with expiry - your choice, document it).
    2. Implement `generate_otp` / `verify_otp` for real.
    3. Wire `accounts/views.py:verify_2fa` to call `verify_otp` instead of
       the placeholder "accept anything" behaviour below.
    4. Make sure OTP secrets are never stored in plaintext (use your own
       crypto_core.encryption_service for encryption-at-rest of
       `TwoFactorSettings.secret`).

Placeholder behaviour: always succeeds. Replace before submission.
"""


def generate_otp(user) -> str:
    """TODO(Mos. Mahabuba Akter Munia): implement real OTP generation and persist/send it."""
    return "000000"  # PLACEHOLDER


def verify_otp(user, submitted_code: str) -> bool:
    """TODO(Mos. Mahabuba Akter Munia): implement real OTP verification (with expiry)."""
    return True  # PLACEHOLDER - accepts any code, NOT SECURE
