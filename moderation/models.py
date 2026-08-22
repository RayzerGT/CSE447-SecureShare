"""
moderation/models.py
Assigned to: Mos. Mahabuba Akter Munia (backs her audit log viewer, user
management, admin-role management, and reports pages - across both the
admin panel's user_management() and the developer panel's manage_admins()/
manage_users() in portal_views.py - see todo.txt)
"""

from django.conf import settings
from django.db import models

from messaging.models import Message
from posts.models import Post


class AuditLog(models.Model):
    """
    REQUIREMENT (Idea.pdf): "Interface to view searchable system logs,
    including failed login attempts, 2FA failures, privilege escalation
    events, key access logs, and content deletions."
    """

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
    """
    REQUIREMENT (Idea.pdf): "Account state controls: Admin can temporarily
    lock, suspend, or ban user accounts (e.g., following suspicious activity
    or failed login thresholds)."
    """

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        LOCKED = "locked", "Locked"
        SUSPENDED = "suspended", "Suspended"
        BANNED = "banned", "Banned"

    # Statuses that block login entirely (checked in accounts/views.py::login_view
    # and moderation/portal_views.py::portal_login - see is_blocked_for below).
    BLOCKING_STATUSES = {Status.LOCKED, Status.SUSPENDED, Status.BANNED}

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="account_state")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    reason = models.CharField(max_length=255, blank=True)

    # A "warning" is a strike that does NOT block login (unlike lock/suspend/
    # ban) - just a count admins/developers can act on however they see fit.
    warning_count = models.PositiveIntegerField(default=0)

    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    changed_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AccountState({self.user.username}: {self.status}, warnings={self.warning_count})"

    @classmethod
    def is_blocked_for(cls, user) -> bool:
        """True if this user's account state should block them from logging in."""
        state = cls.objects.filter(user=user).first()
        return bool(state and state.status in cls.BLOCKING_STATUSES)


class Report(models.Model):
    """
    REQUIREMENT: "Users can report friends, posts, messages which will be
    handled by admins" - one report model, exactly one of post/reported_user/
    message set per row (enforced in the view layer, not a DB constraint,
    to keep this simple). Reviewed as "tickets" via the admin panel's
    Reports menu (moderation/views.py::reports_list). Reporting a post also
    flags it (Post.is_flagged) so it shows in Global Content Moderation too.
    """

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
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    resolved_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        target = {"post": f"post={self.post_id}", "user": f"user={self.reported_user_id}", "message": f"message={self.message_id}"}[self.kind]
        return f"Report({target}, by={self.reporter.username}, resolved={self.is_resolved})"
