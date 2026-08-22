"""
moderation/models.py
Assigned to: Mos. Mahabuba Akter Munia (backs her audit log viewer, user
management, admin-role management, and reports pages - across both the
admin panel's user_management() and the developer panel's manage_admins()/
manage_users() in portal_views.py - see todo.txt)
"""

from django.conf import settings
from django.db import models

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

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="account_state")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    reason = models.CharField(max_length=255, blank=True)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="+"
    )
    changed_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"AccountState({self.user.username}: {self.status})"


class Report(models.Model):
    """
    A regular user's report of a post, reviewed via the admin panel's
    "Reports" menu (moderation/views.py::reports_list). Submitting a report
    also flags the post (Post.is_flagged) so it shows up in the existing
    Global Content Moderation view too.
    """

    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="reports_filed")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="reports")
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
        return f"Report(post={self.post_id}, by={self.reporter.username}, resolved={self.is_resolved})"
