"""
moderation/views.py
Split ownership - see todo.txt:
    - dashboard()                                            -> Razeen Hassan (admin panel shell)
    - audit_logs(), user_management(), content_moderation()  -> Mos. Mahabuba Akter Munia

TODO(Razeen Hassan): replace @admin_required (currently is_staff-based) with
the finished RBAC core once moderation/permissions.py is implemented for real.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from accounts.models import ActiveSession, Profile, Role
from accounts.security.session_manager import revoke_all_sessions_for_user
from posts.models import Post
from social.models import Comment

from .logging_service import log_event
from .models import AccountState, AuditLog
from .permissions import admin_required

User = get_user_model()


@login_required
@admin_required
def dashboard(request):
    """Owner: Razeen Hassan. Admin Security Dashboard: system health, total users, active sessions, alerts."""
    stats = {
        "total_users": User.objects.count(),
        "active_sessions": ActiveSession.objects.filter(is_revoked=False).count(),
        "flagged_posts": Post.objects.filter(is_flagged=True, is_deleted=False).count(),
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


@login_required
@admin_required
def user_management(request):
    """Owner: Mos. Mahabuba Akter Munia. Role promote/demote calls into Razeen's Role choices."""
    if request.method == "POST":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"))
        action = request.POST.get("action")

        if action == "promote":
            profile, _ = Profile.objects.get_or_create(user=target_user)
            profile.role = Role.ADMIN
            profile.save(update_fields=["role"])
            log_event(request.user, "role_promoted", target=target_user)
        elif action == "demote":
            profile, _ = Profile.objects.get_or_create(user=target_user)
            profile.role = Role.USER
            profile.save(update_fields=["role"])
            log_event(request.user, "role_demoted", target=target_user)
        elif action in {"lock", "suspend", "ban", "reactivate"}:
            state, _ = AccountState.objects.get_or_create(user=target_user)
            status_map = {
                "lock": AccountState.Status.LOCKED,
                "suspend": AccountState.Status.SUSPENDED,
                "ban": AccountState.Status.BANNED,
                "reactivate": AccountState.Status.ACTIVE,
            }
            state.status = status_map[action]
            state.changed_by = request.user
            state.save(update_fields=["status", "changed_by", "changed_at"])
            log_event(request.user, f"account_{action}", target=target_user)
        elif action == "revoke_sessions":
            # Session Revocation & Emergency Controls - logic lives in Razeen's
            # accounts/security/session_manager.py; this admin-panel trigger is yours.
            revoke_all_sessions_for_user(target_user)
            log_event(request.user, "sessions_revoked", target=target_user)

        return redirect("moderation:user_management")

    users = User.objects.select_related("profile", "account_state").all()
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
