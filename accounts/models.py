from django.conf import settings
from django.db import models

class Role(models.TextChoices):

    USER = "user", "Standard User"
    ADMIN = "admin", "Admin"
    DEVELOPER = "developer", "Developer"

class Profile(models.Model):

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.USER)

    full_name = models.CharField(max_length=150, blank=True)
    bio = models.TextField(blank=True)
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)

    encrypted_contact_info = models.TextField(blank=True, help_text="Ciphertext blob (contact info).")

    public_key_reference = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile({self.user.username})"

    @property
    def is_admin(self):
        return self.role == Role.ADMIN

    @property
    def is_developer(self):
        return self.role == Role.DEVELOPER

class SecurityQuestion(models.TextChoices):
    FIRST_TEACHER = "first_teacher", "What was the name of your first teacher?"
    FIRST_PET = "first_pet", "What was the name of your first pet?"
    BIRTH_CITY = "birth_city", "In which city were you born?"
    CHILDHOOD_FRIEND = "childhood_friend", "What is the name of your childhood best friend?"
    PRIMARY_SCHOOL = "primary_school", "What was the name of your primary school?"
    FAVOURITE_DISH = "favourite_dish", "What is your favourite dish?"
    MOTHERS_MAIDEN_NAME = "mothers_maiden_name", "What is your mother's maiden name?"


class TwoFactorSettings(models.Model):

    class Method(models.TextChoices):
        SECURITY_QUESTION = "security_question", "Security Question"

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="two_factor")
    is_enabled = models.BooleanField(default=False)
    method = models.CharField(max_length=32, choices=Method.choices, default=Method.SECURITY_QUESTION)
    question = models.CharField(max_length=32, choices=SecurityQuestion.choices, blank=True)
    answer_hash = models.CharField(max_length=255, blank=True)
    secret = models.CharField(max_length=255, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    @property
    def is_configured(self) -> bool:
        return bool(self.is_enabled and self.question and self.answer_hash)

    @property
    def question_text(self) -> str:
        return SecurityQuestion(self.question).label if self.question else ""

    def __str__(self):
        return f"2FA({self.user.username}, enabled={self.is_enabled})"

class ActiveSession(models.Model):

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
