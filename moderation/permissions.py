from functools import wraps

from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

from accounts.models import Role

class Permission:

    USE_SOCIAL_SITE = "use_social_site"
    CREATE_POST = "create_post"
    SEND_MESSAGE = "send_message"
    LIKE_AND_COMMENT = "like_and_comment"
    SUBMIT_REPORT = "submit_report"
    MANAGE_OWN_PROFILE = "manage_own_profile"
    MANAGE_OWN_SESSIONS = "manage_own_sessions"

    VIEW_ADMIN_DASHBOARD = "view_admin_dashboard"
    VIEW_AUDIT_LOG = "view_audit_log"
    HANDLE_REPORTS = "handle_reports"
    MODERATE_CONTENT = "moderate_content"
    MANAGE_USER_ACCOUNTS = "manage_user_accounts"
    REVOKE_USER_SESSIONS = "revoke_user_sessions"

    VIEW_RAW_DATABASE = "view_raw_database"
    CREATE_ADMIN = "create_admin"
    REMOVE_ADMIN = "remove_admin"
    BAN_ADMIN = "ban_admin"

ROLE_PERMISSIONS = {
    Role.USER: frozenset({
        Permission.USE_SOCIAL_SITE,
        Permission.CREATE_POST,
        Permission.SEND_MESSAGE,
        Permission.LIKE_AND_COMMENT,
        Permission.SUBMIT_REPORT,
        Permission.MANAGE_OWN_PROFILE,
        Permission.MANAGE_OWN_SESSIONS,
    }),
    Role.ADMIN: frozenset({
        Permission.VIEW_ADMIN_DASHBOARD,
        Permission.VIEW_AUDIT_LOG,
        Permission.HANDLE_REPORTS,
        Permission.MODERATE_CONTENT,
        Permission.MANAGE_USER_ACCOUNTS,
        Permission.REVOKE_USER_SESSIONS,
    }),
    Role.DEVELOPER: frozenset({
        Permission.VIEW_RAW_DATABASE,
        Permission.CREATE_ADMIN,
        Permission.REMOVE_ADMIN,
        Permission.BAN_ADMIN,
        Permission.MANAGE_USER_ACCOUNTS,
        Permission.REVOKE_USER_SESSIONS,
    }),
}

ROLE_ALLOWED_PREFIXES = {
    Role.ADMIN: ("/moderation/", "/accounts/logout/", "/static/", "/media/"),
    Role.DEVELOPER: ("/portal/", "/accounts/logout/", "/static/", "/media/"),
}

ROLE_HOME = {
    Role.USER: "posts:feed",
    Role.ADMIN: "moderation:dashboard",
    Role.DEVELOPER: "portal:developer_dashboard",
}

def home_url_for(user) -> str:
    return ROLE_HOME.get(role_of(user), "posts:feed")

def role_of(user) -> str:
    if not user or not user.is_authenticated:
        return None
    profile = getattr(user, "profile", None)
    return getattr(profile, "role", None) or Role.USER

_ALL_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())

def permissions_for(user) -> frozenset:
    return ROLE_PERMISSIONS.get(role_of(user), frozenset())

def has_permission(user, permission: str) -> bool:
    if permission not in _ALL_PERMISSIONS:
        raise ValueError(f"unknown permission: {permission!r}")
    return permission in permissions_for(user)

def require_permission(permission: str):

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not has_permission(request.user, permission):
                raise PermissionDenied(f"This action requires the '{permission}' privilege.")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator

def role_required(*roles):

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if role_of(request.user) not in roles:
                raise PermissionDenied("Your role does not have access to this area.")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator

def admin_required(view_func):
    return role_required(Role.ADMIN)(view_func)

def developer_required(view_func):
    return role_required(Role.DEVELOPER)(view_func)

class RoleAccessMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            role = role_of(request.user)
            allowed = ROLE_ALLOWED_PREFIXES.get(role)
            if allowed and not request.path.startswith(allowed):
                return redirect(ROLE_HOME[role])
        return self.get_response(request)
