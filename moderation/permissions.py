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

Placeholder: `admin_required` currently only checks `is_staff` (Django's
built-in flag) as a stand-in, and `has_permission` always returns True.
NOT SECURE - replace before submission.
"""

from functools import wraps

from django.core.exceptions import PermissionDenied


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
