"""
social/context_processors.py
Assigned to: Mos. Mahabuba Akter Munia (owner of the friends system)

Makes the pending-friend-request count available to every template so the
"Friends" nav item can show a notification badge (templates/navbar.html),
the way Instagram badges its activity tab. Purely a UI affordance - the
actual accept/reject permission check lives in social/views.py.
"""

from .models import FriendRequest


def pending_requests(request):
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {}
    # Admin/Developer accounts have no social surface at all, so skip the
    # query entirely for them (see moderation/permissions.py's hierarchy).
    profile = getattr(user, "profile", None)
    if profile and (profile.is_admin or profile.is_developer):
        return {}
    return {"pending_request_count": FriendRequest.objects.filter(receiver=user).count()}
