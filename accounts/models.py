"""
accounts/models.py

Data model for user identity, role, 2FA settings, and active session tracking.

NOTE on encryption: the project requires user info (username, email, contact
info) to be stored encrypted and decrypted on retrieval, using asymmetric
algorithms implemented from scratch (see crypto_core/encryption_service.py,
owned by Mos. Mahabuba Akter Munia - built on Afnan's RSA and Razeen's ECC).
The fields below therefore store ciphertext blobs (Base64/text) rather than
plaintext columns. The call site is in views.py:register() (Razeen's), which
needs to call Munia's encryption_service to populate these fields instead of
storing plaintext.
"""

from django.conf import settings
from django.db import models


class Role(models.TextChoices):
    """RBAC roles. Enforcement logic lives in moderation/permissions.py (Razeen Hassan)."""

    USER = "user", "Standard User"
    ADMIN = "admin", "Admin"


class Profile(models.Model):
    """Extends django.contrib.auth.User with SecureShare-specific fields."""

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.USER)

    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)

    # TODO(Mos. Mahabuba Akter Munia): populate via crypto_core.encryption_service
    # instead of plaintext. These are intentionally text/blob fields so they can hold
    # ciphertext once encryption is wired in; until then, views.py stores/reads them
    # as plain text placeholders.
    encrypted_contact_info = models.TextField(blank=True, help_text="Ciphertext blob (contact info).")

    # TODO(Afnan Satter): each user needs an asymmetric keypair reference for
    # encrypting their profile/post data. Public key can be stored here; private key
    # material belongs in crypto_core.KeyRecord (your KMM), never in plaintext on
    # this model.
    public_key_reference = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile({self.user.username})"

    @property
    def is_admin(self):
        return self.role == Role.ADMIN


class TwoFactorSettings(models.Model):
    """
    TODO(Mos. Mahabuba Akter Munia): implement real TOTP/email-OTP generation &
    verification in accounts/security/two_factor.py. `secret` should be generated
    by that module, not left blank.
    """

    class Method(models.TextChoices):
        TOTP = "totp", "Authenticator App (TOTP)"
        EMAIL_OTP = "email_otp", "Email OTP"

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor")
    is_enabled = models.BooleanField(default=False)
    method = models.CharField(max_length=16, choices=Method.choices, default=Method.EMAIL_OTP)
    secret = models.CharField(max_length=255, blank=True)  # TODO(Mos. Mahabuba Akter Munia): store securely, not plaintext
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"2FA({self.user.username}, enabled={self.is_enabled})"


class ActiveSession(models.Model):
    """
    Backs the user-facing "active sessions" dashboard and enforced session
    timeouts (accounts/security/session_manager.py). `expires_at` is set once,
    at login, to `created_at + SESSION_TIMEOUT_MINUTES` - it is an absolute
    cutoff, not a sliding/idle timeout, so the session ends a fixed amount of
    time after login regardless of activity.
    """

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="active_sessions")
    session_key = models.CharField(max_length=255, unique=True)
    device_info = models.CharField(max_length=255, blank=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_active_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(blank=True, null=True)
    is_revoked = models.BooleanField(default=False)

    def __str__(self):
        return f"Session({self.user.username}, status={self.status})"

    @property
    def is_expired(self) -> bool:
        from django.utils import timezone

        return self.expires_at is not None and timezone.now() >= self.expires_at

    @property
    def status(self) -> str:
        if self.is_revoked:
            return "Revoked"
        if self.is_expired:
            return "Expired"
        return "Active"
