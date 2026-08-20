"""
moderation/permissions.py
Assigned to: Razeen Hassan (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "Role-Based Access Control (RBAC) must
define separate privileges for administrators and regular users to restrict
sensitive operations." This is the RBAC core - the single source of truth
for permission decisions. Other apps (posts/permissions.py, social/views.py,
moderation/views.py itself) should call into this rather than re-implementing
role checks inline.

TODO(Razeen Hassan):
    1. Define the actual permission matrix (which roles can do what -
       view audit logs, delete any post, manage roles, moderate content, etc.).
    2. Implement `has_permission` / `role_required` / `admin_required` for real.
    3. Replace the naive `Profile.role == "admin"` checks scattered around
       accounts/social/posts/moderation with calls into this module.

Also home to `developer_required`, which gates the raw-database-viewer
portal (moderation/portal_views.py::developer_dashboard) - a separate
privileged tier from admin, see accounts.models.Role's DEVELOPER option.

Placeholder: `admin_required` currently only checks `is_staff` (Django's
built-in flag) as a stand-in, `developer_required` only checks
`is_superuser`, and `has_permission` always returns True.
NOT SECURE - replace before submission.

--------------------------------------------------------------------------
HIERARCHY (per project decision): Developer > Admin > User, but this is
NOT a "higher role can do everything a lower role can" hierarchy - each
role is walled off to its OWN area only:
    - User: the social site (feed/upload/messaging/social) - nothing
      moderation/portal-related.
    - Admin: the admin panel (/moderation/) ONLY. No feed/upload/messaging.
      Can manage USER accounts only (lock/suspend/ban) - cannot touch
      other Admin or Developer accounts, and cannot promote anyone to
      Admin (that's a Developer-only power - see manage_admins()).
    - Developer: the developer panel (/portal/) ONLY. No feed/upload/
      messaging, no admin panel. Can promote/demote the Admin role
      (moderation/portal_views.py::manage_admins) and separately manage
      USER accounts (moderation/portal_views.py::manage_users) - two
      distinct menus, kept apart from each other.
`RoleAccessMiddleware` below enforces the "walled off to your own area"
part; admin_required/developer_required enforce which VIEWS you can reach
at all; the queryset scoping inside user_management()/manage_admins()/
manage_users() enforces who you can act ON.
--------------------------------------------------------------------------
"""

from functools import wraps

from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

from accounts.models import Role


def has_permission(user, permission: str) -> bool:
    """TODO(Razeen Hassan): implement the real RBAC permission matrix."""
    return True  # PLACEHOLDER - grants every permission to every authenticated user


def admin_required(view_func):
    """TODO(Razeen Hassan): base this on accounts.models.Role via has_permission(), not is_staff."""

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        profile_is_admin = getattr(getattr(request.user, "profile", None), "is_admin", False)
        if not (request.user.is_authenticated and (request.user.is_staff or profile_is_admin)):
            raise PermissionDenied("Admin privileges required.")
        return view_func(request, *args, **kwargs)

    return wrapper


def developer_required(view_func):
    """
    TODO(Razeen Hassan): base this on accounts.models.Role.DEVELOPER via
    has_permission(), not is_superuser. Keep this check SEPARATE from
    admin_required - developer and admin are distinct privilege tiers even
    though one person could hold both roles.
    """

    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        profile_is_developer = getattr(getattr(request.user, "profile", None), "is_developer", False)
        if not (request.user.is_authenticated and (request.user.is_superuser or profile_is_developer)):
            raise PermissionDenied("Developer privileges required.")
        return view_func(request, *args, **kwargs)

    return wrapper


class RoleAccessMiddleware:
    """
    REQUIREMENT: "developers and admins can't be part of the social media
    itself... no feed, upload, or messaging... Admins will only have
    access to the admin panel and developers will only have access to the
    developer panel."

    Runs on every request; if the logged-in user is an Admin or Developer,
    it restricts them to their own panel + logout (and static/media) and
    redirects anything else there instead. This is what actually keeps them
    out of posts/messaging/social, not just hidden nav links - a role check
    on the middleware level so no individual view can be missed.

    TODO(Razeen Hassan): once the real RBAC permission matrix exists, this
    should probably be driven by it too instead of a hardcoded prefix list.
    """

    ADMIN_ALLOWED_PREFIXES = ("/moderation/", "/accounts/logout/", "/static/", "/media/")
    DEVELOPER_ALLOWED_PREFIXES = ("/portal/", "/accounts/logout/", "/static/", "/media/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            profile = getattr(request.user, "profile", None)
            role = getattr(profile, "role", None)

            if role == Role.ADMIN and not request.path.startswith(self.ADMIN_ALLOWED_PREFIXES):
                return redirect("moderation:dashboard")
            if role == Role.DEVELOPER and not request.path.startswith(self.DEVELOPER_ALLOWED_PREFIXES):
                return redirect("portal:developer_dashboard")

        return self.get_response(request)
