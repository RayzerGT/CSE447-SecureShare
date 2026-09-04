from accounts.models import Role

from .models import UserNotice


def account_notices(request):
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return {}
    profile = getattr(user, "profile", None)
    if profile is not None and getattr(profile, "role", Role.USER) != Role.USER:
        return {}
    return {"account_notices": list(UserNotice.unread_for(user)[:5])}
