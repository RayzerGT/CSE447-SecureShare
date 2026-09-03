"""
accounts/security/session_manager.py
Assigned to: Razeen Hassan (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "Secure session management must protect
authentication tokens and prevent session hijacking."

Four simple rules, all enforced server-side by SecureSessionMiddleware on
every authenticated request:

    1. ABSOLUTE TIMEOUT   - a session dies SESSION_TIMEOUT_MINUTES after
                            login, regardless of activity. Not a sliding
                            idle timeout: staying active cannot keep a
                            session alive forever.
    2. DEVICE BINDING     - the session is pinned to the browser and IP that
                            created it. A stolen cookie replayed from a
                            different browser or address does not work.
                            This is the anti-hijacking rule.
    3. REVOCATION         - revoking a session kills it immediately, on the
                            next request, for both the self-service "log out
                            everywhere" button and admin/developer emergency
                            revocation.
    4. FIXATION DEFENCE   - the session key is rotated at login, so a
                            pre-login cookie cannot be reused afterwards.

DESIGN NOTE - why there is no custom token scheme:
    An earlier note here proposed replacing Django's session cookie with a
    hand-rolled signed token. That was dropped deliberately. Django's cookie
    is already a random opaque key (not user data), it is HttpOnly +
    SameSite=Lax + optionally Secure (see settings.py), and the actual
    session state lives server-side in the database where we can expire and
    revoke it. Writing our own token format would add signing/parsing code
    - and a new class of bugs - without making anything safer. The
    project's from-scratch requirement is about ENCRYPTION ALGORITHMS
    (RSA/ECC), not about re-implementing cookie plumbing.

    So the security here comes from the four rules above, which are the
    parts that actually matter, and each is a handful of lines.
"""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout as django_logout
from django.contrib.sessions.models import Session
from django.core.exceptions import PermissionDenied
from django.utils import timezone

from accounts.models import ActiveSession


def _client_ip(request) -> str:
    """
    Best-effort client IP. Honours X-Forwarded-For only for its first entry
    (the original client) since anything after that is proxy chain.
    """
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "") or ""


def _user_agent(request) -> str:
    return request.META.get("HTTP_USER_AGENT", "")[:255]


def issue_session(request, user, device_info: str = "") -> ActiveSession:
    """
    Record the session created by this login.

    Call this AFTER django.contrib.auth.login(), which rotates the session
    key - that rotation is rule 4 (fixation defence), and it is why the key
    read below is the post-login one.
    """
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


# check_session outcomes.
SESSION_OK = "ok"
SESSION_DEAD = "dead"        # expired or revoked -> log the user out
SESSION_MISMATCH = "mismatch"  # wrong device -> refuse this request only


def check_session(request):
    """
    Apply the rules to the current request.

    Returns (outcome, reason). Kept as a pure check - no side effects - so
    the middleware stays readable and the behaviour is easy to test.
    """
    session = ActiveSession.objects.filter(
        user=request.user, session_key=request.session.session_key
    ).first()
    if session is None:
        # Nothing recorded for this key (e.g. a Django /django-admin/ login).
        # Not ours to police.
        return SESSION_OK, None

    if session.is_revoked:
        return SESSION_DEAD, "This session was ended. Please log in again."

    if session.is_expired:
        return SESSION_DEAD, f"Your session expired after {settings.SESSION_TIMEOUT_MINUTES} minute(s). Please log in again."

    # --- device binding (rule 2, anti-hijacking) ---
    #
    # A mismatch means someone is replaying this session's cookie from
    # another browser or address. We refuse THAT request and leave the
    # session itself untouched.
    #
    # It is tempting to revoke on mismatch instead ("assume compromise"),
    # but the cookie is a single shared session key: revoking would log out
    # the legitimate owner too, which hands the attacker a reliable way to
    # kick the victim off at will. Refusing without revoking blocks the
    # attacker completely while leaving the real user working.
    if session.device_info and session.device_info != _user_agent(request):
        return SESSION_MISMATCH, "Session does not belong to this browser."

    if getattr(settings, "SESSION_BIND_IP", True):
        current_ip = _client_ip(request) or None
        if session.ip_address and current_ip and session.ip_address != current_ip:
            return SESSION_MISMATCH, "Session does not belong to this network address."

    return SESSION_OK, None


def validate_session(request) -> bool:
    """True if the current request carries a healthy session."""
    if not request.user.is_authenticated:
        return False
    outcome, _ = check_session(request)
    return outcome == SESSION_OK


def revoke_session(session: ActiveSession) -> None:
    """
    End a session for real: flag the row AND delete the underlying Django
    session, so the cookie the user still holds is dead immediately rather
    than merely marked.
    """
    session.is_revoked = True
    session.save(update_fields=["is_revoked"])
    Session.objects.filter(session_key=session.session_key).delete()


def revoke_all_sessions_for_user(user) -> int:
    """
    Used by self-service "log out of all devices" and by admin/developer
    emergency revocation (moderation/views.py, portal_views.py).
    """
    sessions = list(ActiveSession.objects.filter(user=user, is_revoked=False))
    if not sessions:
        return 0
    ActiveSession.objects.filter(pk__in=[s.pk for s in sessions]).update(is_revoked=True)
    Session.objects.filter(session_key__in=[s.session_key for s in sessions]).delete()
    return len(sessions)


class SecureSessionMiddleware:
    """
    Enforces every rule in this module on each authenticated request.

    Ordering matters (see settings.MIDDLEWARE): this must run AFTER
    AuthenticationMiddleware (it needs request.user) and MessageMiddleware
    (it uses the messages framework), and BEFORE RoleAccessMiddleware, so a
    dead session is logged out before any role-based redirect looks at it.
    """

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
                # Refuse this request only - deliberately no logout and no
                # revocation, so a replayed cookie cannot be used to kick the
                # legitimate owner off. See check_session().
                raise PermissionDenied(reason)

        return self.get_response(request)
