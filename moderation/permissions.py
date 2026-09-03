"""
moderation/permissions.py
Assigned to: Razeen Hassan (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "Role-Based Access Control (RBAC) must
define separate privileges for administrators and regular users to restrict
sensitive operations." This is the RBAC core - the single source of truth
for permission decisions. Other apps (social/views.py, moderation/views.py,
moderation/portal_views.py) call into this rather than re-implementing role
checks inline.

Scope note: this is about ADMIN vs DEVELOPER vs USER privileges only. Post
visibility is not an RBAC concern - every post is simply friends-only (see
posts/views.py), and the old Public/Private/Role-Restricted feature that
used to sit on top of this module has been removed.

--------------------------------------------------------------------------
HIERARCHY (per project decision): Developer > Admin > User in seniority, but
this is deliberately NOT an inheritance hierarchy - a higher role does NOT
automatically get the lower roles' privileges. Each role is walled off to
its OWN area, and ROLE_PERMISSIONS below spells out each role's privileges
in full rather than deriving them from another role:
    - User: the social site (feed/upload/messaging/social) - nothing
      moderation/portal-related.
    - Admin: the admin panel (/moderation/) ONLY. No feed/upload/messaging.
      Can manage USER accounts only (warn/lock/suspend/ban) - cannot touch
      other Admin or Developer accounts, and cannot create new admins
      (Developer-only - see manage_admins()).
    - Developer: the developer panel (/portal/) ONLY. No feed/upload/
      messaging, no admin panel. Creates new admins by registering them
      (NOT promotion), can remove (demote) or ban an existing admin, and
      separately manages USER accounts - two distinct menus.

Note what this means concretely: an Admin cannot read the raw database, and
a Developer cannot work the report queue. Neither can post or send a message.
That is intentional, not an oversight.

THREE LAYERS OF ENFORCEMENT (defence in depth - each catches what the
others might miss):
    1. RoleAccessMiddleware  - which AREA of the site you may be in at all.
                               Runs on every request, so no view can be
                               forgotten.
    2. admin_required / developer_required / require_permission
                             - which VIEWS you may reach.
    3. queryset scoping inside user_management()/manage_admins()/
       manage_users() (profile__role=...) - which ACCOUNTS you may act on,
       so a hand-crafted POST still 404s on a target of the wrong role.
--------------------------------------------------------------------------

DESIGN NOTE - why Django's is_staff/is_superuser are not used here:
    The previous placeholder granted admin access to anyone with
    `is_staff`, and developer access to anyone with `is_superuser`. Those
    are Django's own flags for its built-in /django-admin/ site, and they
    are not the project's roles. Leaving them in would mean a Django
    superuser silently held Developer privileges in our system without ever
    appearing as one in the Role column - exactly the kind of invisible
    privilege the RBAC requirement exists to prevent. Authorisation here is
    decided solely by accounts.models.Profile.role.
"""

from functools import wraps

from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

from accounts.models import Role


# ==========================================================================
# THE PERMISSION MATRIX - three roles, three disjoint areas
# ==========================================================================
#
#                                        | USER | ADMIN | DEVELOPER |
#   -------------------------------------+------+-------+-----------+
#   SOCIAL SITE                          |      |       |           |
#     use_social_site (feed/profiles)    |  YES |   -   |     -     |
#     create_post                        |  YES |   -   |     -     |
#     send_message                       |  YES |   -   |     -     |
#     like_and_comment                   |  YES |   -   |     -     |
#     submit_report                      |  YES |   -   |     -     |
#     manage_own_profile                 |  YES |   -   |     -     |
#     manage_own_sessions                |  YES |   -   |     -     |
#   -------------------------------------+------+-------+-----------+
#   ADMIN PANEL  (/moderation/)          |      |       |           |
#     view_admin_dashboard               |   -  |  YES  |     -     |
#     view_audit_log                     |   -  |  YES  |     -     |
#     handle_reports (ticket queue)      |   -  |  YES  |     -     |
#     moderate_content                   |   -  |  YES  |     -     |
#   -------------------------------------+------+-------+-----------+
#   DEVELOPER PANEL  (/portal/)          |      |       |           |
#     view_raw_database                  |   -  |   -   |    YES    |
#     create_admin                       |   -  |   -   |    YES    |
#     remove_admin                       |   -  |   -   |    YES    |
#     ban_admin                          |   -  |   -   |    YES    |
#   -------------------------------------+------+-------+-----------+
#   SHARED BY BOTH PRIVILEGED ROLES      |      |       |           |
#     manage_user_accounts (warn/ban)    |   -  |  YES  |    YES    |
#     revoke_user_sessions               |   -  |  YES  |    YES    |
#   -------------------------------------+------+-------+-----------+
#
# Read the columns, not the rows: no column is a superset of another. The
# only deliberate overlap is the bottom block - both an Admin and a
# Developer can discipline a Standard User, which is the "two separate
# menus" requirement (moderation/views.py::user_management for admins,
# moderation/portal_views.py::manage_users for developers).
#
# Everything else is disjoint, and that is the point: an Admin cannot read
# the raw database, a Developer cannot work the report queue, and neither
# can post or send a message.
# ==========================================================================


class Permission:
    """
    Every sensitive operation in the system, named. Grouped by the area that
    owns it. Using constants rather than bare strings means a typo is an
    AttributeError at import time instead of a silent permission failure.
    """

    # --- social site (Standard Users) ---
    USE_SOCIAL_SITE = "use_social_site"        # feed, profiles, friends
    CREATE_POST = "create_post"
    SEND_MESSAGE = "send_message"
    LIKE_AND_COMMENT = "like_and_comment"
    SUBMIT_REPORT = "submit_report"            # report a post/user/message
    MANAGE_OWN_PROFILE = "manage_own_profile"
    MANAGE_OWN_SESSIONS = "manage_own_sessions"  # "log out of all devices"

    # --- admin panel ---
    VIEW_ADMIN_DASHBOARD = "view_admin_dashboard"
    VIEW_AUDIT_LOG = "view_audit_log"
    HANDLE_REPORTS = "handle_reports"          # the ticket queue
    MODERATE_CONTENT = "moderate_content"      # delete flagged posts/comments
    MANAGE_USER_ACCOUNTS = "manage_user_accounts"  # warn/lock/suspend/ban a USER
    REVOKE_USER_SESSIONS = "revoke_user_sessions"  # admin-triggered revocation

    # --- developer panel ---
    VIEW_RAW_DATABASE = "view_raw_database"
    CREATE_ADMIN = "create_admin"
    REMOVE_ADMIN = "remove_admin"
    BAN_ADMIN = "ban_admin"


# The permission matrix. Each role's privileges are listed in full - nothing
# is inherited from another role (see the HIERARCHY note above).
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

# Which URL prefixes each privileged role is confined to. A role absent from
# this map (i.e. Role.USER) is not area-restricted by the middleware - the
# social site is the default area, and the few /moderation/ endpoints a
# regular user legitimately needs (submitting a report) are guarded by view
# decorators instead.
ROLE_ALLOWED_PREFIXES = {
    Role.ADMIN: ("/moderation/", "/accounts/logout/", "/static/", "/media/"),
    Role.DEVELOPER: ("/portal/", "/accounts/logout/", "/static/", "/media/"),
}

# Each role's landing page: where login sends them, and where the middleware
# sends a privileged user who strays outside their own area.
ROLE_HOME = {
    Role.USER: "posts:feed",
    Role.ADMIN: "moderation:dashboard",
    Role.DEVELOPER: "portal:developer_dashboard",
}


def home_url_for(user) -> str:
    """
    The named URL this user's role lands on after logging in.

    There is one login page for everybody (accounts/views.py::login_view);
    this is what makes that possible - the role decides the destination, so
    no separate per-role login endpoint is needed.
    """
    return ROLE_HOME.get(role_of(user), "posts:feed")


def role_of(user) -> str:
    """
    The RBAC role for `user`. Falls back to Role.USER when there is no
    Profile yet (e.g. an account made by `createsuperuser`) - least
    privilege of the three, so a missing profile can never grant admin or
    developer access.
    """
    if not user or not user.is_authenticated:
        return None
    profile = getattr(user, "profile", None)
    return getattr(profile, "role", None) or Role.USER


# Every permission granted to at least one role, used to reject typo'd names.
_ALL_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())


def permissions_for(user) -> frozenset:
    """Every permission `user` holds. Empty for anonymous users."""
    return ROLE_PERMISSIONS.get(role_of(user), frozenset())


def has_permission(user, permission: str) -> bool:
    """
    The single authorisation predicate for the whole project. Everything
    else in this module is built on top of it.
    """
    if permission not in _ALL_PERMISSIONS:
        # A typo'd/retired permission name must never be treated as "allowed".
        raise ValueError(f"unknown permission: {permission!r}")
    return permission in permissions_for(user)


# --- view decorators --------------------------------------------------------


def require_permission(permission: str):
    """
    Gate a view on a single permission:

        @require_permission(Permission.HANDLE_REPORTS)
        def reports_list(request): ...
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not has_permission(request.user, permission):
                raise PermissionDenied(f"This action requires the '{permission}' privilege.")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def role_required(*roles):
    """Gate a view on holding one of `roles` outright."""

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if role_of(request.user) not in roles:
                raise PermissionDenied("Your role does not have access to this area.")
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def admin_required(view_func):
    """
    Admin panel gate. Kept as its own name because it is used across
    moderation/views.py; it is now a thin wrapper over the real matrix
    rather than an is_staff check.
    """
    return role_required(Role.ADMIN)(view_func)


def developer_required(view_func):
    """
    Developer panel gate. Deliberately SEPARATE from admin_required -
    developer and admin are distinct tiers, and neither implies the other.
    """
    return role_required(Role.DEVELOPER)(view_func)


# --- middleware -------------------------------------------------------------


class RoleAccessMiddleware:
    """
    REQUIREMENT: "developers and admins can't be part of the social media
    itself... no feed, upload, or messaging... Admins will only have access
    to the admin panel and developers will only have access to the developer
    panel."

    Runs on every request: if the logged-in user holds a role that is
    confined to an area (ROLE_ALLOWED_PREFIXES), any request outside that
    area is redirected back to their own home page. This is what actually
    keeps a privileged account out of posts/messaging/social - not just
    hidden nav links - and being middleware means an individual view cannot
    be forgotten.

    It is layer 1 of 3; see the module docstring.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            role = role_of(request.user)
            allowed = ROLE_ALLOWED_PREFIXES.get(role)
            if allowed and not request.path.startswith(allowed):
                return redirect(ROLE_HOME[role])
        return self.get_response(request)
