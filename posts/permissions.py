"""
posts/permissions.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

REQUIREMENT (CSE447 Project.pdf / Idea.pdf): "Post Privacy Settings: Users
can mark uploads as Public, Private (only viewable by the owner), or
Role-Restricted. Access controls strictly enforce who can view each image."
This is the RBAC-driven visibility enforcement layer, built on top of the
RBAC core (moderation/permissions.py, owned by Razeen Hassan).

TODO(Mos. Mahabuba Akter Munia):
    1. Implement `can_view_post` for real: PUBLIC -> everyone; PRIVATE ->
       owner + admins only; ROLE_RESTRICTED -> users whose
       accounts.Profile.role matches post.allowed_role (or admins).
    2. Call into Razeen's RBAC helpers (moderation/permissions.py) rather
       than duplicating role-check logic.
    3. Use this from posts/views.py (Afnan's) - feed filtering + detail view
       403s - call sites are already marked with matching TODOs there.

Placeholder behaviour: everything is visible to everyone. NOT SECURE - replace.
"""

from posts.models import Visibility


def can_view_post(user, post) -> bool:
    """TODO(Mos. Mahabuba Akter Munia): implement real visibility + RBAC enforcement."""
    return True  # PLACEHOLDER - ignores post.visibility entirely


def visible_posts_queryset(user, base_queryset):
    """
    TODO(Mos. Mahabuba Akter Munia): filter base_queryset down to only posts
    `user` is allowed to see, per can_view_post's rules (do this at the DB
    level for the feed, rather than filtering in Python for every post).
    """
    return base_queryset  # PLACEHOLDER - returns everything, including private posts
