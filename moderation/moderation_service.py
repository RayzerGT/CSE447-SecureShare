from datetime import timedelta

from django.utils import timezone

from accounts.security.session_manager import revoke_all_sessions_for_user
from social.models import Friendship

from .logging_service import log_event
from .models import AccountState, UserNotice

STATUS_ACTIONS = {"warn", "lock", "suspend", "ban", "reactivate"}
ALL_ACTIONS = STATUS_ACTIONS | {"revoke_sessions"}


def _notify(user, level, headline, body, actor):
    return UserNotice.objects.create(
        user=user, level=level, headline=headline, body=body, issued_by=actor
    )


def warn_user(actor, target, reason="") -> dict:
    state = AccountState.for_user(target)
    state.warning_count += 1
    state.changed_by = actor
    state.save(update_fields=["warning_count", "changed_by", "changed_at"])

    remaining = AccountState.WARNINGS_BEFORE_SUSPENSION - state.warning_count
    if remaining > 0:
        body = (
            f"{reason}\n\n" if reason else ""
        ) + (
            f"This is warning {state.warning_count} of {AccountState.WARNINGS_BEFORE_SUSPENSION}. "
            f"{remaining} more and your account will be suspended automatically."
        )
        _notify(
            target,
            UserNotice.Level.WARNING,
            f"You have received a warning from a moderator ({state.warning_count} of {AccountState.WARNINGS_BEFORE_SUSPENSION})",
            body,
            actor,
        )
        log_event(actor, "account_warned", target=target, metadata={"warning_count": state.warning_count, "reason": reason})
        return {"escalated": False, "warning_count": state.warning_count}

    log_event(actor, "account_warned", target=target, metadata={"warning_count": state.warning_count, "reason": reason})
    suspend_user(
        actor,
        target,
        reason=f"Automatic suspension after {state.warning_count} warnings."
        + (f" Most recent: {reason}" if reason else ""),
        automatic=True,
    )
    return {"escalated": True, "warning_count": state.warning_count}


def suspend_user(actor, target, reason="", days=None, automatic=False) -> AccountState:
    days = days or AccountState.DEFAULT_SUSPENSION_DAYS
    state = AccountState.for_user(target)
    state.status = AccountState.Status.SUSPENDED
    state.reason = reason
    state.suspended_until = timezone.now() + timedelta(days=days)
    state.changed_by = actor
    state.save(update_fields=["status", "reason", "suspended_until", "changed_by", "changed_at"])

    revoke_all_sessions_for_user(target)
    _notify(
        target,
        UserNotice.Level.SUSPENSION,
        f"Your account was suspended until {state.suspended_until:%d %b %Y, %H:%M}",
        reason or "A moderator suspended this account.",
        actor,
    )
    log_event(
        actor,
        "account_suspended",
        target=target,
        metadata={"reason": reason, "days": days, "until": state.suspended_until.isoformat(), "automatic": automatic},
    )
    return state


def lock_user(actor, target, reason="") -> AccountState:
    state = AccountState.for_user(target)
    state.status = AccountState.Status.LOCKED
    state.reason = reason
    state.suspended_until = None
    state.changed_by = actor
    state.save(update_fields=["status", "reason", "suspended_until", "changed_by", "changed_at"])

    revoke_all_sessions_for_user(target)
    log_event(actor, "account_locked", target=target, metadata={"reason": reason})
    return state


def ban_user(actor, target, reason="") -> AccountState:
    state = AccountState.for_user(target)
    state.status = AccountState.Status.BANNED
    state.reason = reason
    state.suspended_until = None
    state.changed_by = actor
    state.save(update_fields=["status", "reason", "suspended_until", "changed_by", "changed_at"])

    removed = Friendship.remove_all_for(target)
    if removed:
        log_event(actor, "friendships_removed_on_ban", target=target, metadata={"count": removed})
    revoke_all_sessions_for_user(target)
    log_event(actor, "account_banned", target=target, metadata={"reason": reason})
    return state


def reactivate_user(actor, target, reason="", clear_warnings=False) -> AccountState:
    state = AccountState.for_user(target)
    was = state.status
    state.status = AccountState.Status.ACTIVE
    state.reason = ""
    state.suspended_until = None
    fields = ["status", "reason", "suspended_until", "changed_by", "changed_at"]
    if clear_warnings:
        state.warning_count = 0
        fields.append("warning_count")
    state.changed_by = actor
    state.save(update_fields=fields)

    UserNotice.objects.filter(
        user=target,
        acknowledged_at__isnull=True,
        level__in=[UserNotice.Level.WARNING, UserNotice.Level.SUSPENSION],
    ).update(acknowledged_at=timezone.now())

    _notify(
        target,
        UserNotice.Level.REINSTATEMENT,
        "Your account has been reinstated",
        reason or "A moderator restored full access to this account.",
        actor,
    )
    log_event(
        actor,
        "account_reactivated",
        target=target,
        metadata={"previous_status": was, "reason": reason, "warnings_cleared": clear_warnings},
    )
    return state


def notify_content_removed(actor, target, headline, reason=""):
    _notify(target, UserNotice.Level.CONTENT_REMOVED, headline, reason, actor)


def apply_account_status_action(actor, target_user, action, reason="", days=None) -> bool:
    if action == "warn":
        warn_user(actor, target_user, reason)
        return True
    if action == "suspend":
        suspend_user(actor, target_user, reason, days)
        return True
    if action == "lock":
        lock_user(actor, target_user, reason)
        return True
    if action == "ban":
        ban_user(actor, target_user, reason)
        return True
    if action == "reactivate":
        reactivate_user(actor, target_user, reason)
        return True
    if action == "revoke_sessions":
        revoke_all_sessions_for_user(target_user)
        log_event(actor, "sessions_revoked", target=target_user, metadata={"reason": reason})
        return True
    return False
