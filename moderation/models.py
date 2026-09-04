from django.conf import settings
from django.db import models
from django.utils import timezone

from messaging.models import Message
from posts.models import Post

class AuditLog(models.Model):

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="audit_events"
    )
    action = models.CharField(max_length=64)
    target_type = models.CharField(max_length=64, blank=True)
    target_id = models.CharField(max_length=64, blank=True)
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    metadata = models.JSONField(blank=True, default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        actor_name = self.actor.username if self.actor else "system"
        return f"AuditLog({actor_name}: {self.action})"

class AccountState(models.Model):

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        LOCKED = "locked", "Locked"
        SUSPENDED = "suspended", "Suspended"
        BANNED = "banned", "Banned"

    BLOCKING_STATUSES = {Status.LOCKED, Status.SUSPENDED, Status.BANNED}

    WARNINGS_BEFORE_SUSPENSION = 3
    DEFAULT_SUSPENSION_DAYS = 7

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="account_state")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    reason = models.CharField(max_length=255, blank=True)

    warning_count = models.PositiveIntegerField(default=0)
    suspended_until = models.DateTimeField(blank=True, null=True)

    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    changed_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AccountState({self.user.username}: {self.status}, warnings={self.warning_count})"

    def suspension_expired(self) -> bool:
        return (
            self.status == self.Status.SUSPENDED
            and self.suspended_until is not None
            and self.suspended_until <= timezone.now()
        )

    def lift_expired_suspension(self) -> bool:
        if not self.suspension_expired():
            return False
        self.status = self.Status.ACTIVE
        self.reason = ""
        self.suspended_until = None
        self.save(update_fields=["status", "reason", "suspended_until", "changed_at"])
        return True

    def is_blocking(self) -> bool:
        if self.lift_expired_suspension():
            return False
        return self.status in self.BLOCKING_STATUSES

    def block_message(self) -> str:
        if self.status == self.Status.BANNED:
            headline = "This account has been permanently banned."
        elif self.status == self.Status.SUSPENDED:
            if self.suspended_until:
                headline = f"This account is suspended until {self.suspended_until:%d %b %Y, %H:%M}."
            else:
                headline = "This account is suspended."
        elif self.status == self.Status.LOCKED:
            headline = "This account has been locked by an administrator."
        else:
            return ""
        return f"{headline} Reason: {self.reason}" if self.reason else headline

    @classmethod
    def for_user(cls, user):
        state, _ = cls.objects.get_or_create(user=user)
        return state

    @classmethod
    def is_blocked_for(cls, user) -> bool:
        state = cls.objects.filter(user=user).first()
        return bool(state and state.is_blocking())

    @classmethod
    def block_message_for(cls, user) -> str:
        state = cls.objects.filter(user=user).first()
        return state.block_message() if state else ""


class UserNotice(models.Model):

    class Level(models.TextChoices):
        WARNING = "warning", "Warning"
        SUSPENSION = "suspension", "Suspension"
        REINSTATEMENT = "reinstatement", "Reinstatement"
        CONTENT_REMOVED = "content_removed", "Content removed"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="notices")
    level = models.CharField(max_length=20, choices=Level.choices, default=Level.WARNING)
    headline = models.CharField(max_length=160)
    body = models.TextField(blank=True)

    issued_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    acknowledged_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"UserNotice({self.user.username}: {self.level})"

    @classmethod
    def unread_for(cls, user):
        return cls.objects.filter(user=user, acknowledged_at__isnull=True)

class Report(models.Model):

    class Kind(models.TextChoices):
        POST = "post", "Post"
        USER = "user", "User"
        MESSAGE = "message", "Message"

    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="reports_filed")
    kind = models.CharField(max_length=10, choices=Kind.choices, default=Kind.POST)

    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="reports", null=True, blank=True)
    reported_user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="reports_against", null=True, blank=True
    )
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name="reports", null=True, blank=True)

    reason = models.TextField(blank=True)

    is_resolved = models.BooleanField(default=False)
    resolution = models.CharField(max_length=32, blank=True)
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    resolved_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def subject_user(self):
        if self.kind == self.Kind.USER:
            return self.reported_user
        if self.kind == self.Kind.POST and self.post_id:
            return self.post.owner
        if self.kind == self.Kind.MESSAGE and self.message_id:
            return self.message.sender
        return None

    def __str__(self):
        target = {"post": f"post={self.post_id}", "user": f"user={self.reported_user_id}", "message": f"message={self.message_id}"}[self.kind]
        return f"Report({target}, by={self.reporter.username}, resolved={self.is_resolved})"
