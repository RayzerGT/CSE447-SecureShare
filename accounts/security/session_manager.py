from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout as django_logout
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from accounts.models import ActiveSession

def _client_ip(request) -> str:
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or ""

def _user_agent(request) -> str:
    return request.META.get("HTTP_USER_AGENT", "")[:255]

def issue_session(request, user, device_info: str = "") -> ActiveSession:
    session_key = request.session.session_key or ""
    expires_at = timezone.now() + timezone.timedelta(seconds=settings.APP_SESSION_TIMEOUT_SECONDS)
    user_agent = device_info or _user_agent(request)
    ip_address = _client_ip(request) or None

    record, created = ActiveSession.objects.get_or_create(
        user=user,
        session_key=session_key or f"placeholder-{user.pk}-{user_agent}",
        defaults={"device_info": user_agent, "ip_address": ip_address, "expires_at": expires_at},
    )
    if not created:
        record.device_info = user_agent
        record.ip_address = ip_address
        record.expires_at = expires_at
        record.is_revoked = False
        record.save(update_fields=["device_info", "ip_address", "expires_at", "is_revoked"])
    return record

SESSION_OK = "ok"
SESSION_DEAD = "dead"
SESSION_MISMATCH = "mismatch"

def check_session(request):
    session = ActiveSession.objects.filter(
        user=request.user, session_key=request.session.session_key
    ).first()
    if session is None:
        return SESSION_OK, None

    if session.is_revoked:
        return SESSION_DEAD, "This session was ended. Please log in again."

    if session.is_expired:
        return SESSION_DEAD, f"Your session expired after {settings.SESSION_TIMEOUT_MINUTES} minute(s). Please log in again."

    if session.device_info and session.device_info != _user_agent(request):
        return SESSION_MISMATCH, "Session does not belong to this browser."

    if getattr(settings, "SESSION_BIND_IP", True):
        current_ip = _client_ip(request) or None
        if session.ip_address and current_ip and session.ip_address != current_ip:
            return SESSION_MISMATCH, "Session does not belong to this network address."

    return SESSION_OK, None

def validate_session(request) -> bool:
    if not request.user.is_authenticated:
        return False
    outcome, _ = check_session(request)
    return outcome == SESSION_OK

def revoke_session(session: ActiveSession) -> None:
    session.is_revoked = True
    session.save(update_fields=["is_revoked"])
    Session.objects.filter(session_key=session.session_key).delete()

def revoke_all_sessions_for_user(user) -> int:
    sessions = list(ActiveSession.objects.filter(user=user, is_revoked=False))
    if not sessions:
        return 0
    ActiveSession.objects.filter(pk__in=[s.pk for s in sessions]).update(is_revoked=True)
    Session.objects.filter(session_key__in=[s.session_key for s in sessions]).delete()
    return len(sessions)

class SecureSessionMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            outcome, reason = check_session(request)

            if outcome == SESSION_DEAD:
                session = ActiveSession.objects.filter(
                    user=request.user, session_key=request.session.session_key
                ).first()
                if session is not None:
                    revoke_session(session)
                django_logout(request)
                messages.info(request, reason)

            elif outcome == SESSION_MISMATCH:
                raise PermissionDenied(reason)

        return self.get_response(request)
