from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.models import ActiveSession, Role
from accounts.security.session_manager import revoke_all_sessions_for_user
from messaging.models import Message
from posts.models import Post
from social.models import Comment, Friendship

from .logging_service import log_event
from .models import AccountState, AuditLog, Report
from .permissions import admin_required

User = get_user_model()

@login_required
@admin_required
def dashboard(request):
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
    query = request.GET.get("q", "")
    logs = AuditLog.objects.all()
    if query:
        logs = logs.filter(action__icontains=query)
    return render(request, "moderation/audit_logs.html", {"logs": logs[:200], "query": query})

def apply_account_status_action(actor, target_user, action) -> bool:
    if action in {"lock", "suspend", "ban", "reactivate", "warn"}:
        state, _ = AccountState.objects.get_or_create(user=target_user)

        if action == "warn":
            state.warning_count += 1
            state.changed_by = actor
            state.save(update_fields=["warning_count", "changed_by", "changed_at"])
            log_event(actor, "account_warned", target=target_user, metadata={"warning_count": state.warning_count})
            return True

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

        if action == "ban":
            removed = Friendship.remove_all_for(target_user)
            if removed:
                log_event(actor, "friendships_removed_on_ban", target=target_user, metadata={"count": removed})
            revoke_all_sessions_for_user(target_user)

        return True
    if action == "revoke_sessions":
        revoke_all_sessions_for_user(target_user)
        log_event(actor, "sessions_revoked", target=target_user)
        return True
    return False

@login_required
@admin_required
def user_management(request):
    if request.method == "POST":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"), profile__role=Role.USER)
        apply_account_status_action(request.user, target_user, request.POST.get("action"))
        return redirect("moderation:user_management")

    users = User.objects.select_related("profile", "account_state").filter(profile__role=Role.USER)
    return render(request, "moderation/user_management.html", {"users": users})

@login_required
@admin_required
def content_moderation(request):
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
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)
    if request.method == "POST":
        reason = request.POST.get("reason", "").strip()
        Report.objects.create(reporter=request.user, kind=Report.Kind.POST, post=post, reason=reason)
        post.is_flagged = True
        post.save(update_fields=["is_flagged"])
        log_event(request.user, "post_reported", target=post)
    return redirect("posts:detail", post_id=post.id)

@login_required
def report_user(request, username):
    target = get_object_or_404(User, username=username)
    if request.method == "POST" and target.pk != request.user.pk:
        reason = request.POST.get("reason", "").strip()
        Report.objects.create(reporter=request.user, kind=Report.Kind.USER, reported_user=target, reason=reason)
        log_event(request.user, "user_reported", target=target)
    return redirect("accounts:profile_detail", username=target.username)

@login_required
def report_message(request, message_id):
    message = get_object_or_404(Message, pk=message_id)
    if request.method == "POST" and message.sender_id != request.user.id:
        reason = request.POST.get("reason", "").strip()
        Report.objects.create(reporter=request.user, kind=Report.Kind.MESSAGE, message=message, reason=reason)
        log_event(request.user, "message_reported", target=message)
    return redirect("messaging:thread", username=message.sender.username)

@login_required
@admin_required
def reports_list(request):
    if request.method == "POST":
        report = get_object_or_404(Report, pk=request.POST.get("report_id"))
        action = request.POST.get("action")

        message_to_delete = None

        if report.kind == Report.Kind.POST and action == "delete_post" and report.post:
            report.post.is_deleted = True
            report.post.save(update_fields=["is_deleted"])
            log_event(request.user, "post_deleted_by_admin", target=report.post, metadata={"via": "report"})
        elif report.kind == Report.Kind.USER and action in {"warn", "suspend", "ban"} and report.reported_user:
            apply_account_status_action(request.user, report.reported_user, action)
        elif report.kind == Report.Kind.MESSAGE and action == "delete_message" and report.message:
            message_to_delete = report.message
            log_event(request.user, "message_deleted_by_admin", target=report.message, metadata={"via": "report"})

        report.is_resolved = True
        report.resolved_by = request.user
        report.resolved_at = timezone.now()
        report.message = None if message_to_delete else report.message
        report.save()
        log_event(request.user, "report_resolved", target=report)

        if message_to_delete:
            message_to_delete.delete()

        return redirect("moderation:reports_list")

    pending_reports = Report.objects.filter(is_resolved=False).select_related(
        "post", "reported_user", "message", "reporter"
    )
    return render(request, "moderation/reports_list.html", {"reports": pending_reports, "kinds": Report.Kind})
