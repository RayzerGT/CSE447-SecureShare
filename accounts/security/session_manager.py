"""
accounts/security/session_manager.py

REQUIREMENT (CSE447 Project.pdf): "Secure session management must protect
authentication tokens and prevent session hijacking." (Idea.pdf: HTTP-only +
SameSite cookies or short-lived JWTs, enforced timeouts, secure revocation on
logout, CSRF/XSS protection for session tokens.)

Implemented now: enforced absolute session timeout. Once a user logs in, an
ActiveSession row is stamped with
`expires_at = now + settings.APP_SESSION_TIMEOUT_SECONDS` (driven by the
SESSION_TIMEOUT_MINUTES env var). Every authenticated request is checked
against that timestamp by `SecureSessionMiddleware` below; once it's passed,
the session is revoked and the user is logged out server-side.

This is deliberately independent of Django's own SESSION_COOKIE_AGE (which is
left generous - see settings.py) so that OUR enforcement is what actually
ends the session, not just an incidental side effect of the cookie/session
store expiring on its own.

Still TODO(Razeen Hassan):
    1. This still rides on Django's default session cookie (signed, not a
       custom token scheme) - swap for a from-scratch signed/short-lived
       token if the assignment requires it.
    2. Hijacking protections beyond what Django gives for free (e.g. binding
       a session to the issuing IP/user-agent and rejecting mismatches).
"""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout as django_logout
from django.utils import timezone

from accounts.models import ActiveSession


def issue_session(request, user, device_info: str = "") -> ActiveSession:
    """
    Create (or refresh) the ActiveSession row for this login, stamping an
    absolute expiry `SESSION_COOKIE_AGE` seconds from now.
    """
    session_key = request.session.session_key or ""
    expires_at = timezone.now() + timezone.timedelta(seconds=settings.APP_SESSION_TIMEOUT_SECONDS)
    record, created = ActiveSession.objects.get_or_create(
        user=user,
        session_key=session_key or f"placeholder-{user.pk}-{device_info}",
        defaults={"device_info": device_info, "expires_at": expires_at},
    )
    if not created:
        record.device_info = device_info
        record.expires_at = expires_at
        record.is_revoked = False
        record.save(update_fields=["device_info", "expires_at", "is_revoked"])
    return record


def validate_session(request) -> bool:
    """
    True if the request's session is authenticated, has a matching
    non-revoked ActiveSession row, and hasn't passed its expiry.
    """
    if not request.user.is_authenticated:
        return False

    session = ActiveSession.objects.filter(
        user=request.user, session_key=request.session.session_key
    ).first()
    if session is None or session.is_revoked or session.is_expired:
        return False
    return True


def revoke_session(session: ActiveSession) -> None:
    """TODO(Razeen Hassan): also invalidate the underlying token/cookie, not just the DB flag."""
    session.is_revoked = True
    session.save(update_fields=["is_revoked"])


def revoke_all_sessions_for_user(user) -> int:
    """Used by both self-service logout-everywhere and admin emergency revocation."""
    sessions = ActiveSession.objects.filter(user=user, is_revoked=False)
    count = sessions.count()
    sessions.update(is_revoked=True)
    return count


class SecureSessionMiddleware:
    """
    Enforces the SESSION_TIMEOUT_MINUTES absolute session timeout on every
    request. Must run after AuthenticationMiddleware (needs request.user) and
    MessageMiddleware (uses the messages framework).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            session = ActiveSession.objects.filter(
                user=request.user, session_key=request.session.session_key
            ).first()

            if session is not None and not session.is_revoked and session.is_expired:
                session.is_revoked = True
                session.save(update_fields=["is_revoked"])
                django_logout(request)
                messages.info(
                    request,
                    f"Your session expired after {settings.SESSION_TIMEOUT_MINUTES} minute(s). Please log in again.",
                )

        return self.get_response(request)
