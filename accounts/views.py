from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.db.models import Count, Q
from django.shortcuts import redirect, render
from django.utils.safestring import mark_safe

from .forms import LoginForm, ProfileForm, RegistrationForm, TwoFactorForm
from .security import google_oauth

from posts.models import Post
from social.models import FriendRequest, Friendship
from .models import ActiveSession, Profile, Role, TwoFactorSettings
from .security import session_manager, two_factor

from moderation.models import AccountState
from moderation.logging_service import log_event
from crypto_core.encryption_service import EncryptionService

from moderation.permissions import home_url_for, role_of

def register(request):
    google_profile = request.session.get("pending_google_profile")
    initial = {}
    if google_profile:
        initial = {
            "email": google_profile.get("email", ""),
            "first_name": google_profile.get("given_name", ""),
            "last_name": google_profile.get("family_name", ""),
        }

    if request.method == "POST":
        form = RegistrationForm(request.POST, initial=initial, google_signup=bool(google_profile))
        if form.is_valid():
            user = form.save(commit=False)
            if google_profile:
                user.set_unusable_password()
            else:
                user.set_password(form.cleaned_data["password"])
            user.save()

            full_name = f"{form.cleaned_data['first_name']} {form.cleaned_data['last_name']}".strip()
            contact_info = form.cleaned_data.get("contact_info", "").strip()
            profile = Profile.objects.create(
                user=user,
                full_name=full_name,
                encrypted_contact_info=(
                    EncryptionService.encrypt_profile_data(user, contact_info) if contact_info else ""
                ),
            )
            TwoFactorSettings.objects.create(user=user)

            if google_profile and google_profile.get("picture"):
                fetched = google_oauth.download_profile_picture(google_profile["picture"])
                if fetched is not None:
                    picture_bytes, extension = fetched
                    profile.avatar.save(f"google_{user.pk}.{extension}", ContentFile(picture_bytes), save=True)

            request.session.pop("pending_google_profile", None)
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

    user = User.objects.filter(email=profile["email"]).first() if profile["email"] else None
    if user is not None:
        if AccountState.is_blocked_for(user):
            messages.error(request, "This account is locked, suspended, or banned. Contact an administrator.")
            return redirect("accounts:login")

        if two_factor.is_required_for(user):
            request.session["pending_2fa_user_id"] = user.pk
            return redirect("accounts:verify_2fa")

        django_login(request, user)
        session_manager.issue_session(request, user, device_info=request.META.get("HTTP_USER_AGENT", ""))
        messages.success(
            request,
            f"Logged in with Google. This session will expire in {settings.SESSION_TIMEOUT_MINUTES} minute(s).",
        )
        return redirect("posts:feed")

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
                if role_of(user) == Role.USER and two_factor.is_required_for(user):
                    request.session["pending_2fa_user_id"] = user.pk
                    return redirect("accounts:verify_2fa")

                django_login(request, user)
                session_manager.issue_session(request, user, device_info=request.META.get("HTTP_USER_AGENT", ""))
                messages.success(
                    request,
                    f"Logged in. This session will expire in {settings.SESSION_TIMEOUT_MINUTES} minute(s).",
                )
                return redirect(home_url_for(user))
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
        if form.is_valid() and two_factor.verify_code(user, form.cleaned_data["code"]):
            del request.session["pending_2fa_user_id"]
            django_login(request, user)
            session_manager.issue_session(request, user, device_info=request.META.get("HTTP_USER_AGENT", ""))
            log_event(user, "two_factor_verified", request=request)
            messages.success(
                request,
                f"Logged in. This session will expire in {settings.SESSION_TIMEOUT_MINUTES} minute(s).",
            )
            return redirect(home_url_for(user))
        log_event(user, "two_factor_failed", request=request)
        messages.error(request, "That code is not correct or has expired.")
    else:
        form = TwoFactorForm()
    return render(
        request,
        "accounts/verify_2fa.html",
        {"form": form},
    )

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

        if action == "begin_2fa":
            two_factor.begin_enrolment(request.user)
            return redirect("accounts:sessions")
        elif action == "confirm_2fa":
            if two_factor.confirm_enrolment(request.user, request.POST.get("code", "")):
                log_event(request.user, "two_factor_enabled", request=request)
                messages.success(request, "Two-factor authentication is on. Your app will supply a code at every login.")
            else:
                messages.error(request, "That code is not correct. Check your authenticator app and try again.")
            return redirect("accounts:sessions")
        elif action == "cancel_2fa" or action == "disable_2fa":
            was_enabled = two_fa.is_configured
            two_factor.disable(request.user)
            if was_enabled:
                log_event(request.user, "two_factor_disabled", request=request)
                messages.info(request, "Two-factor authentication is off.")
            return redirect("accounts:sessions")
        elif action == "logout_all":
            session_manager.revoke_all_sessions_for_user(request.user)
            return redirect("accounts:sessions")

    two_fa.refresh_from_db()
    enrolment = None
    if two_factor.is_enrolling(request.user):
        secret = two_factor.current_secret(request.user)
        enrolment = {
            "secret": secret,
            "qr_svg": mark_safe(two_factor.qr_svg(two_factor.provisioning_uri(request.user, secret))),
            "algorithm": two_factor.ALGORITHM,
        }

    return render(
        request,
        "accounts/sessions.html",
        {
            "sessions": sessions,
            "two_fa": two_fa,
            "enrolment": enrolment,
            "session_timeout_minutes": settings.SESSION_TIMEOUT_MINUTES,
        },
    )
