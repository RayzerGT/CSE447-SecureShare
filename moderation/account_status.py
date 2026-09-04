from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect

from .models import AccountState

EXEMPT_PREFIXES = ("/accounts/login/", "/accounts/logout/", "/accounts/register/", "/static/", "/media/")


class AccountStatusMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if (
            user is not None
            and user.is_authenticated
            and not request.path.startswith(EXEMPT_PREFIXES)
        ):
            state = AccountState.objects.filter(user=user).first()
            if state is not None and state.is_blocking():
                message = state.block_message()
                logout(request)
                messages.error(request, message, extra_tags="sticky")
                return redirect("accounts:login")

        return self.get_response(request)
