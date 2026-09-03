"""
accounts/views.py

User onboarding & authentication, 2FA verification step, profile view/edit,
and the user security/account dashboard (active sessions + logout-everywhere).

This file is split across two teammates - see todo.txt for the full picture:
    - register(), login_view(), logout_view(), sessions_dashboard(),
      profile_view(), profile_edit()                                -> Razeen Hassan
    - verify_2fa()                                                  -> Mos. Mahabuba Akter Munia

Wiring points - see todo.txt for who owns what:
    - accounts/security/hashing.py           - password hash+salt
    - accounts/security/two_factor.py        - OTP generation/verification
    - accounts/security/session_manager.py   - secure session issuance/revocation

Registration writes a User + Profile + TwoFactorSettings row to the database
immediately; login authenticates against that stored (hashed) password and
records/updates an ActiveSession row - both are fully functional against a
real MySQL database, not just a UI mockup.
"""

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.db.models import Count, Q
from django.shortcuts import redirect, render

from .forms import LoginForm, ProfileForm, RegistrationForm, TwoFactorForm
from .security import google_oauth

# TODO(Razeen Hassan): these are ordinary functional imports for the
# friend-count/post-count stats shown on profile_view below - not a crypto
# wiring point, same cross-app pattern as posts/views.py importing
# social.models.Friendship.
from posts.models import Post
from social.models import FriendRequest, Friendship
from .models import ActiveSession, Profile, Role, TwoFactorSettings
from .security import session_manager, two_factor

# TODO(Razeen Hassan): moderation.models.AccountState.is_blocked_for() lives
# in Munia's app but is imported here for the login block-check below - this
# is a functional (not crypto) cross-app call, same pattern as posts/views.py
# importing social.models.Friendship.
from moderation.models import AccountState
from moderation.logging_service import log_event

# The RBAC core decides where each role lands after the single shared login.
from moderation.permissions import home_url_for, role_of


def register(request):
    # Set by google_login_callback below when a Google sign-in didn't match
    # an existing account - carries the verified {email, given_name,
    # family_name, picture} through to pre-fill this form.
    google_profile = request.session.get("pending_google_profile")
    initial = {}
    if google_profile:
        initial = {
            "email": google_profile.get("email", ""),
            "first_name": google_profile.get("given_name", ""),
            "last_name": google_profile.get("family_name", ""),
        }

    if request.method == "POST":
        # `initial` must be passed here too, not just on the GET branch below:
        # the email field is disabled() for a Google signup, and a disabled
        # field's cleaned value comes from form.initial, not from POST data
        # (that's the whole point - it can't be tampered with) - so without
        # this, it silently resolved to "" instead of the verified address.
        form = RegistrationForm(request.POST, initial=initial, google_signup=bool(google_profile))
        if form.is_valid():
            user = form.save(commit=False)
            if google_profile:
                # Authenticated via Google, not a local password - see
                # accounts/security/google_oauth.py for the trust model.
                user.set_unusable_password()
            else:
                # set_password() goes through FromScratchPasswordHasher (see
                # accounts/security/hashing.py + settings.py's PASSWORD_HASHERS) -
                # no direct call to the from-scratch pipeline needed here.
                user.set_password(form.cleaned_data["password"])
            user.save()

            # TODO(Mos. Mahabuba Akter Munia): encrypt contact_info via
            # crypto_core.encryption_service before storing it here.
            full_name = f"{form.cleaned_data['first_name']} {form.cleaned_data['last_name']}".strip()
            profile = Profile.objects.create(
                user=user,
                full_name=full_name,
                encrypted_contact_info=form.cleaned_data.get("contact_info", ""),
            )
            TwoFactorSettings.objects.create(user=user)

            # One-time import of the Google avatar at account creation only -
            # never overwrites it again later, so a user who then uploads
            # their own avatar (accounts/views.py::profile_edit) doesn't get
            # it silently replaced on a future Google login.
            if google_profile and google_profile.get("picture"):
                fetched = google_oauth.download_profile_picture(google_profile["picture"])
                if fetched is not None:
                    picture_bytes, extension = fetched
                    profile.avatar.save(f"google_{user.pk}.{extension}", ContentFile(picture_bytes), save=True)

            request.session.pop("pending_google_profile", None)
            # AUDIT LOG HOOK: registration event
            return redirect("accounts:login")
    else:
        form = RegistrationForm(initial=initial, google_signup=bool(google_profile))
    return render(request, "accounts/register.html", {"form": form, "google_signup": bool(google_profile)})


def google_login_start(request):
    if not google_oauth.is_configured():
        messages.error(request, "Google sign-in is not configured on this server.")
        return redirect("accounts:login")

    state = google_oauth.new_state_token()
    request.session["google_oauth_state"] = state
    return redirect(google_oauth.authorization_url(state))


def google_login_callback(request):
    if not google_oauth.is_configured():
        return redirect("accounts:login")

    expected_state = request.session.pop("google_oauth_state", None)
    code = request.GET.get("code")
    if not code or not expected_state or expected_state != request.GET.get("state"):
        messages.error(request, "Google sign-in failed (invalid or expired request). Please try again.")
        return redirect("accounts:login")

    try:
        profile = google_oauth.fetch_google_profile(code)
    except google_oauth.GoogleOAuthError:
        messages.error(request, "Google sign-in failed. Please try again.")
        return redirect("accounts:login")

    # Existing account with this (Google-verified) email -> log straight in,
    # same as a normal password login from here on.
    user = User.objects.filter(email=profile["email"]).first() if profile["email"] else None
    if user is not None:
        if AccountState.is_blocked_for(user):
            messages.error(request, "This account is locked, suspended, or banned. Contact an administrator.")
            return redirect("accounts:login")

        two_fa, _ = TwoFactorSettings.objects.get_or_create(user=user)
        if two_fa.is_enabled:
            request.session["pending_2fa_user_id"] = user.pk
            two_factor.generate_otp(user)
            return redirect("accounts:verify_2fa")

        django_login(request, user)
        session_manager.issue_session(request, user, device_info=request.META.get("HTTP_USER_AGENT", ""))
        messages.success(
            request,
            f"Logged in with Google. This session will expire in {settings.SESSION_TIMEOUT_MINUTES} minute(s).",
        )
        # AUDIT LOG HOOK: successful Google login
        return redirect("posts:feed")

    # No account for this email yet - hand off to registration, pre-filled.
    request.session["pending_google_profile"] = profile
    return redirect("accounts:register")


def login_view(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(
                request,
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password"],
            )
            if user is not None and AccountState.is_blocked_for(user):
                log_event(user, "login_blocked", request=request)
                messages.error(request, "This account is locked, suspended, or banned. Contact an administrator.")
                return render(
                    request,
                    "accounts/login.html",
                    {"form": LoginForm(), "google_login_available": google_oauth.is_configured()},
                )

            if user is not None:
                # 2FA applies to Standard Users only. Admin and Developer
                # accounts skip it (project decision) - they are routed
                # straight to their own panel below.
                if role_of(user) == Role.USER:
                    two_fa, _ = TwoFactorSettings.objects.get_or_create(user=user)
                    if two_fa.is_enabled:
                        request.session["pending_2fa_user_id"] = user.pk
                        otp = two_factor.generate_otp(user)
                        if settings.DEBUG and otp:
                            messages.info(request, f"Development 2FA code: {otp}")
                        return redirect("accounts:verify_2fa")

                django_login(request, user)
                session_manager.issue_session(request, user, device_info=request.META.get("HTTP_USER_AGENT", ""))
                messages.success(
                    request,
                    f"Logged in. This session will expire in {settings.SESSION_TIMEOUT_MINUTES} minute(s).",
                )
                # AUDIT LOG HOOK: successful login
                return redirect(home_url_for(user))
            # AUDIT LOG HOOK: failed login attempt
            log_event(None, "login_failed", metadata={"username": form.cleaned_data["username"]}, request=request)
    else:
        form = LoginForm()
    return render(
        request,
        "accounts/login.html",
        {"form": form, "google_login_available": google_oauth.is_configured()},
    )


def verify_2fa(request):
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return redirect("accounts:login")
    user = User.objects.get(pk=user_id)

    if AccountState.is_blocked_for(user):
        del request.session["pending_2fa_user_id"]
        messages.error(request, "This account is locked, suspended, or banned. Contact an administrator.")
        return redirect("accounts:login")

    if request.method == "POST":
        form = TwoFactorForm(request.POST)
        if form.is_valid() and two_factor.verify_otp(user, form.cleaned_data["code"]):
            del request.session["pending_2fa_user_id"]
            django_login(request, user)
            session_manager.issue_session(request, user, device_info=request.META.get("HTTP_USER_AGENT", ""))
            log_event(user, "two_factor_verified", request=request)
            messages.success(
                request,
                f"Logged in. This session will expire in {settings.SESSION_TIMEOUT_MINUTES} minute(s).",
            )
            # AUDIT LOG HOOK: successful 2FA
            return redirect("posts:feed")
        # AUDIT LOG HOOK: 2FA failure
        log_event(user, "two_factor_failed", request=request)
    else:
        form = TwoFactorForm()
    return render(request, "accounts/verify_2fa.html", {"form": form})


@login_required
def logout_view(request):
    active = ActiveSession.objects.filter(user=request.user, session_key=request.session.session_key).first()
    if active:
        session_manager.revoke_session(active)
    django_logout(request)
    return redirect("accounts:login")


@login_required
def profile_view(request, username=None):
    user = User.objects.get(username=username) if username else request.user
    profile, _ = Profile.objects.get_or_create(user=user)

    # The profile's own post grid. Someone else's posts are only visible to
    # friends - same friends-only rule the feed enforces (posts/views.py).
    is_friend = Friendship.are_friends(request.user, user)
    posts = Post.objects.none()
    if is_friend:
        posts = (
            Post.objects.filter(owner=user, is_deleted=False)
            .annotate(
                like_count=Count("likes", distinct=True),
                comment_count=Count("comments", filter=Q(comments__is_deleted=False), distinct=True),
            )
        )

    # Which button the visitor should see: add / requested / respond / friends.
    is_self = user.pk == request.user.pk
    if is_self or is_friend:
        friend_status = "self" if is_self else "friends"
    elif FriendRequest.objects.filter(sender=request.user, receiver=user).exists():
        friend_status = "request_sent"
    elif FriendRequest.objects.filter(sender=user, receiver=request.user).exists():
        friend_status = "request_received"
    else:
        friend_status = "none"

    context = {
        "profile_user": user,
        "profile": profile,
        "friend_count": len(Friendship.friend_ids_of(user)),
        "post_count": Post.objects.filter(owner=user, is_deleted=False).count(),
        "is_friend": is_friend,
        "is_self": is_self,
        "friend_status": friend_status,
        "posts": posts,
    }
    return render(request, "accounts/profile.html", context)


@login_required
def profile_edit(request):
    profile, _ = Profile.objects.get_or_create(user=request.user)
    if request.method == "POST":
        form = ProfileForm(request.POST, request.FILES, instance=profile)
        if form.is_valid():
            form.save()
            return redirect("accounts:profile")
    else:
        form = ProfileForm(instance=profile)
    return render(request, "accounts/profile_edit.html", {"form": form})


@login_required
def sessions_dashboard(request):
    sessions = ActiveSession.objects.filter(user=request.user).order_by("-last_active_at")
    two_fa, _ = TwoFactorSettings.objects.get_or_create(user=request.user)

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "toggle_2fa":
            two_fa.is_enabled = not two_fa.is_enabled
            two_fa.save(update_fields=["is_enabled"])
        elif action == "logout_all":
            session_manager.revoke_all_sessions_for_user(request.user)
        return redirect("accounts:sessions")

    return render(
        request,
        "accounts/sessions.html",
        {"sessions": sessions, "two_fa": two_fa, "session_timeout_minutes": settings.SESSION_TIMEOUT_MINUTES},
    )
