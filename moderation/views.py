from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from accounts.models import ActiveSession, Role
from crypto_core.encryption_service import EncryptionService
from messaging.models import Message
from posts.encryption import decrypt_caption, decrypt_image
from posts.imaging import CONTENT_TYPE
from posts.models import Post
from social.models import Comment

from .logging_service import log_event
from .moderation_service import apply_account_status_action, notify_content_removed
from .models import AccountState, AuditLog, Report, UserNotice
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

@login_required
@admin_required
def reported_post_image(request, post_id):
    post = get_object_or_404(Post, pk=post_id)
    image_bytes = decrypt_image(post, prefer_thumbnail=True)
    response = HttpResponse(image_bytes, content_type=CONTENT_TYPE)
    response["Cache-Control"] = "private, max-age=3600"
    response["Content-Length"] = str(len(image_bytes))
    return response


def _preview_post(post):
    if post is None:
        return None
    try:
        post.display_caption = decrypt_caption(post)
    except Exception:
        post.display_caption = "(caption could not be decrypted)"
    return post


def _preview_message(message):
    if message is None:
        return None
    try:
        message.display_body = EncryptionService.decrypt_message(
            message.sender, message.recipient, message.ciphertext, message.mac_tag
        ) if message.ciphertext else message.plaintext_body
    except Exception:
        message.display_body = "(message could not be decrypted)"
    return message


@login_required
@admin_required
def user_management(request):
    if request.method == "POST":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"), profile__role=Role.USER)
        action = request.POST.get("action")
        reason = request.POST.get("reason", "").strip()
        days = request.POST.get("days")
        applied = apply_account_status_action(
            request.user, target_user, action, reason, int(days) if days and days.isdigit() else None
        )
        if applied:
            messages.success(request, _action_summary(action, target_user))
        return redirect("moderation:user_management")

    users = User.objects.select_related("profile", "account_state").filter(profile__role=Role.USER)
    return render(
        request,
        "moderation/user_management.html",
        {
            "users": users,
            "suspension_days": AccountState.DEFAULT_SUSPENSION_DAYS,
            "warnings_before_suspension": AccountState.WARNINGS_BEFORE_SUSPENSION,
        },
    )


def _action_summary(action, target) -> str:
    state = AccountState.objects.filter(user=target).first()
    if action == "warn":
        count = state.warning_count if state else 1
        if state and state.status == AccountState.Status.SUSPENDED:
            return f"{target.username} reached {count} warnings and was suspended automatically until {state.suspended_until:%d %b %Y, %H:%M}."
        return f"{target.username} has been warned ({count} of {AccountState.WARNINGS_BEFORE_SUSPENSION}). They will see it on their feed."
    if action == "suspend":
        return f"{target.username} is suspended until {state.suspended_until:%d %b %Y, %H:%M} and has been signed out."
    if action == "lock":
        return f"{target.username} is locked and has been signed out."
    if action == "ban":
        return f"{target.username} is banned, all friendships removed, and all sessions revoked."
    if action == "reactivate":
        return f"{target.username} has been reinstated and can sign in again."
    if action == "revoke_sessions":
        return f"All sessions for {target.username} have been revoked."
    return "Action applied."

@login_required
@admin_required
def content_moderation(request):
    if request.method == "POST":
        action = request.POST.get("action")
        reason = request.POST.get("reason", "").strip()

        if action == "delete_post":
            post = get_object_or_404(Post, pk=request.POST.get("post_id"))
            post.is_deleted = True
            post.is_flagged = False
            post.save(update_fields=["is_deleted", "is_flagged"])
            Report.objects.filter(post=post, is_resolved=False).update(
                is_resolved=True, resolved_by=request.user, resolved_at=timezone.now()
            )
            notify_content_removed(
                request.user, post.owner, "One of your posts was removed by a moderator", reason
            )
            log_event(request.user, "post_deleted_by_admin", target=post, metadata={"reason": reason})
            messages.success(request, f"Post #{post.pk} removed and {post.owner.username} notified.")
        elif action == "clear_flag":
            post = get_object_or_404(Post, pk=request.POST.get("post_id"))
            post.is_flagged = False
            post.save(update_fields=["is_flagged"])
            Report.objects.filter(post=post, is_resolved=False).update(
                is_resolved=True, resolved_by=request.user, resolved_at=timezone.now()
            )
            log_event(request.user, "post_flag_cleared", target=post, metadata={"reason": reason})
            messages.success(request, f"Post #{post.pk} kept; its reports are closed.")
        elif action == "delete_comment":
            comment = get_object_or_404(Comment, pk=request.POST.get("comment_id"))
            comment.is_deleted = True
            comment.save(update_fields=["is_deleted"])
            notify_content_removed(
                request.user, comment.user, "One of your comments was removed by a moderator", reason
            )
            log_event(request.user, "comment_deleted_by_admin", target=comment, metadata={"reason": reason})
            messages.success(request, f"Comment #{comment.pk} removed and {comment.user.username} notified.")
        return redirect("moderation:content_moderation")

    flagged_posts = [
        _preview_post(post)
        for post in Post.objects.filter(is_flagged=True, is_deleted=False).select_related("owner")
    ]
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
        reason = request.POST.get("reason", "").strip()
        days = request.POST.get("days")
        days = int(days) if days and days.isdigit() else None

        subject = report.subject_user()
        outcome = None
        message_to_delete = None

        if action == "delete_post" and report.post:
            report.post.is_deleted = True
            report.post.is_flagged = False
            report.post.save(update_fields=["is_deleted", "is_flagged"])
            notify_content_removed(
                request.user, report.post.owner, "One of your posts was removed by a moderator", reason
            )
            log_event(request.user, "post_deleted_by_admin", target=report.post, metadata={"via": "report", "reason": reason})
            outcome = f"Post #{report.post_id} removed and {report.post.owner.username} notified."
        elif action == "delete_message" and report.message:
            message_to_delete = report.message
            notify_content_removed(
                request.user, report.message.sender, "One of your messages was removed by a moderator", reason
            )
            log_event(request.user, "message_deleted_by_admin", target=report.message, metadata={"via": "report", "reason": reason})
            outcome = f"Message removed and {report.message.sender.username} notified."
        elif action in {"warn", "suspend", "ban"} and subject is not None:
            apply_account_status_action(request.user, subject, action, reason or report.reason, days)
            outcome = _action_summary(action, subject)
        elif action == "dismiss":
            log_event(request.user, "report_dismissed", target=report, metadata={"reason": reason})
            outcome = "Report dismissed; no action taken against the account."
        else:
            messages.error(request, "That action does not apply to this report.")
            return redirect("moderation:reports_list")

        if report.post_id and action != "delete_post":
            still_open = Report.objects.filter(post_id=report.post_id, is_resolved=False).exclude(pk=report.pk)
            if not still_open.exists():
                Post.objects.filter(pk=report.post_id).update(is_flagged=False)

        report.is_resolved = True
        report.resolved_by = request.user
        report.resolved_at = timezone.now()
        report.resolution = action
        if message_to_delete:
            report.message = None
        report.save()
        log_event(request.user, "report_resolved", target=report, metadata={"action": action})

        if message_to_delete:
            message_to_delete.delete()

        messages.success(request, outcome)
        return redirect("moderation:reports_list")

    pending_reports = Report.objects.filter(is_resolved=False).select_related(
        "post", "post__owner", "reported_user", "message", "message__sender", "message__recipient", "reporter"
    )
    for report in pending_reports:
        _preview_post(report.post)
        _preview_message(report.message)
        report.subject = report.subject_user()
        if report.subject is not None:
            report.subject_state = AccountState.objects.filter(user=report.subject).first()

    return render(
        request,
        "moderation/reports_list.html",
        {
            "reports": pending_reports,
            "kinds": Report.Kind,
            "suspension_days": AccountState.DEFAULT_SUSPENSION_DAYS,
        },
    )


@login_required
def acknowledge_notice(request, notice_id):
    if request.method == "POST":
        notice = get_object_or_404(UserNotice, pk=notice_id, user=request.user)
        if notice.acknowledged_at is None:
            notice.acknowledged_at = timezone.now()
            notice.save(update_fields=["acknowledged_at"])
    return redirect(request.POST.get("next") or "posts:feed")
