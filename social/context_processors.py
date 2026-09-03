from .models import FriendRequest

def pending_requests(request):
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {}
    profile = getattr(user, "profile", None)
    if profile and (profile.is_admin or profile.is_developer):
        return {}
    return {"pending_request_count": FriendRequest.objects.filter(receiver=user).count()}
