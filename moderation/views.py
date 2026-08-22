"""
moderation/views.py
Split ownership - see todo.txt:
    - dashboard()                                                          -> Razeen Hassan (admin panel shell)
    - apply_account_status_action(), audit_logs(), user_management(),
      content_moderation(), submit_report(), reports_list()               -> Mos. Mahabuba Akter Munia

TODO(Razeen Hassan): replace @admin_required (currently is_staff-based) with
the finished RBAC core once moderation/permissions.py is implemented for real.

Portal login (Razeen), the developer raw-DB viewer, and the manage_admins()/
manage_users() developer-panel menus (Munia) all live in portal_views.py,
not here - see that file and todo.txt.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.models import ActiveSession, Role
from accounts.security.session_manager import revoke_all_sessions_for_user
from posts.models import Post
from social.models import Comment

from .logging_service import log_event
from .models import AccountState, AuditLog, Report
from .permissions import admin_required

User = get_user_model()


@login_required
@admin_required
def dashboard(request):
    """Owner: Razeen Hassan. Admin Security Dashboard: system health, total users, active sessions, alerts."""
    stats = {
        "total_users": User.objects.count(),
        "banned_users": AccountState.objects.filter(status=AccountState.Status.BANNED).count(),
        "suspended_users": AccountState.objects.filter(status=AccountState.Status.SUSPENDED).count(),
        "active_sessions": ActiveSession.objects.filter(is_revoked=False).count(),
        "flagged_posts": Post.objects.filter(is_flagged=True, is_deleted=False).count(),
        "pending_reports": Report.objects.filter(is_resolved=False).count(),
        "recent_events": AuditLog.objects.all()[:10],
    }
    return render(request, "moderation/dashboard.html", stats)


@login_required
@admin_required
def audit_logs(request):
    """Owner: Mos. Mahabuba Akter Munia."""
    query = request.GET.get("q", "")
    logs = AuditLog.objects.all()
    if query:
        logs = logs.filter(action__icontains=query)
    return render(request, "moderation/audit_logs.html", {"logs": logs[:200], "query": query})


def apply_account_status_action(actor, target_user, action) -> bool:
    """
    Owner: Mos. Mahabuba Akter Munia

    Shared by admin's user_management() below and the developer's
    manage_users() in portal_views.py - both only ever call this on
    Role.USER accounts (each enforces that scoping itself before calling
    in). Handles lock/suspend/ban/reactivate (AccountState) and
    revoke_sessions (Razeen's accounts/security/session_manager.py).
    Returns False if `action` wasn't a recognized status action (caller
    should ignore/no-op in that case).
    """
    if action in {"lock", "suspend", "ban", "reactivate"}:
        state, _ = AccountState.objects.get_or_create(user=target_user)
        status_map = {
            "lock": AccountState.Status.LOCKED,
            "suspend": AccountState.Status.SUSPENDED,
            "ban": AccountState.Status.BANNED,
            "reactivate": AccountState.Status.ACTIVE,
        }
        state.status = status_map[action]
        state.changed_by = actor
        state.save(update_fields=["status", "changed_by", "changed_at"])
        log_event(actor, f"account_{action}", target=target_user)
        return True
    if action == "revoke_sessions":
        revoke_all_sessions_for_user(target_user)
        log_event(actor, "sessions_revoked", target=target_user)
        return True
    return False


@login_required
@admin_required
def user_management(request):
    """
    Owner: Mos. Mahabuba Akter Munia

    REQUIREMENT: "Admins will only be able to handle users" - no promote/
    demote here (that's the Developer-only "manage admins" power now, see
    portal_views.py::manage_admins), and both the list and the POST target
    are scoped to Role.USER only so an admin can't act on another Admin or
    a Developer account even by hand-crafting a request.
    """
    if request.method == "POST":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"), profile__role=Role.USER)
        apply_account_status_action(request.user, target_user, request.POST.get("action"))
        return redirect("moderation:user_management")

    users = User.objects.select_related("profile", "account_state").filter(profile__role=Role.USER)
    return render(request, "moderation/user_management.html", {"users": users})


@login_required
@admin_required
def content_moderation(request):
    """Owner: Mos. Mahabuba Akter Munia. Global Content Moderation: review flagged posts/comments, delete inappropriate content."""
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "delete_post":
            post = get_object_or_404(Post, pk=request.POST.get("post_id"))
            post.is_deleted = True
            post.save(update_fields=["is_deleted"])
            log_event(request.user, "post_deleted_by_admin", target=post)
        elif action == "delete_comment":
            comment = get_object_or_404(Comment, pk=request.POST.get("comment_id"))
            comment.is_deleted = True
            comment.save(update_fields=["is_deleted"])
            log_event(request.user, "comment_deleted_by_admin", target=comment)
        return redirect("moderation:content_moderation")

    flagged_posts = Post.objects.filter(is_flagged=True, is_deleted=False)
    return render(request, "moderation/content_moderation.html", {"flagged_posts": flagged_posts})


@login_required
def submit_report(request, post_id):
    """
    Owner: Mos. Mahabuba Akter Munia

    Regular-user-facing (no @admin_required - anyone logged in can report a
    post). Flags the post so it also shows up in content_moderation(), and
    creates a Report row with the reporter's stated reason for
    reports_list() below.
    """
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)
    if request.method == "POST":
        reason = request.POST.get("reason", "").strip()
        Report.objects.create(reporter=request.user, post=post, reason=reason)
        post.is_flagged = True
        post.save(update_fields=["is_flagged"])
        log_event(request.user, "post_reported", target=post)
    return redirect("posts:detail", post_id=post.id)


@login_required
@admin_required
def reports_list(request):
    """
    Owner: Mos. Mahabuba Akter Munia

    Admin-facing menu of reports filed by regular users (REQUIREMENT:
    "check reports made by regular users"). Two actions per report: delete
    the reported post outright, or dismiss the report without deleting.
    """
    if request.method == "POST":
        report = get_object_or_404(Report, pk=request.POST.get("report_id"))
        action = request.POST.get("action")

        if action == "delete_post":
            report.post.is_deleted = True
            report.post.save(update_fields=["is_deleted"])
            log_event(request.user, "post_deleted_by_admin", target=report.post, metadata={"via": "report"})

        report.is_resolved = True
        report.resolved_by = request.user
        report.resolved_at = timezone.now()
        report.save(update_fields=["is_resolved", "resolved_by", "resolved_at"])
        log_event(request.user, "report_resolved", target=report)
        return redirect("moderation:reports_list")

    pending_reports = Report.objects.filter(is_resolved=False).select_related("post", "reporter")
    return render(request, "moderation/reports_list.html", {"reports": pending_reports})
