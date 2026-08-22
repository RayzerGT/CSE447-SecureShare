"""
moderation/portal_views.py
Split ownership - see todo.txt:
    - portal_login()                        -> Razeen Hassan (RBAC core owner -
                                                this is the gate that decides
                                                who even gets in)
    - developer_dashboard(), manage_admins(),
      manage_users()                        -> Mos. Mahabuba Akter Munia

A separate login endpoint (/portal/login/) for admins and developers, kept
apart from the regular /accounts/login/ used by everyone else. Same
credentials/password check as regular login (there's only one User table -
this isn't a second account system), but success here checks role and
routes to a privileged dashboard instead of the normal feed.

HIERARCHY (see moderation/permissions.py for the full writeup): Developers
manage the Admin role itself (manage_admins) and separately manage Standard
User accounts (manage_users) - two distinct menus. Admins can only manage
Standard User accounts (moderation/views.py::user_management) - they can't
create other admins or touch Developer accounts.
"""

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import login as django_login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from accounts.forms import LoginForm
from accounts.models import Profile, Role, TwoFactorSettings
from accounts.security import session_manager

from .forms import AdminCreationForm
from .logging_service import log_event
from .models import AccountState
from .permissions import developer_required
from .views import apply_account_status_action

User = get_user_model()


def portal_login(request):
    """
    Owner: Razeen Hassan

    TODO(Razeen Hassan):
        1. This currently skips the 2FA step that regular login goes
           through (accounts/views.py::login_view) - for a privileged
           portal, 2FA arguably should be mandatory rather than optional.
           Decide and wire it in (coordinate with Munia on
           accounts/security/two_factor.py).
        2. Once developer_required / admin_required in permissions.py use
           the real RBAC matrix instead of is_staff/is_superuser
           placeholders, this view's role check still doesn't need to
           change - it only needs to know WHICH dashboard to send someone
           to, not re-implement the permission decision itself.
    """
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            user = authenticate(
                request,
                username=form.cleaned_data["username"],
                password=form.cleaned_data["password"],
            )
            profile = getattr(user, "profile", None) if user else None
            is_admin = user and (user.is_staff or getattr(profile, "is_admin", False))
            is_developer = user and (user.is_superuser or getattr(profile, "is_developer", False))

            if user is not None and AccountState.is_blocked_for(user):
                messages.error(request, "This account is locked, suspended, or banned.")
                return render(request, "moderation/portal_login.html", {"form": LoginForm()})

            if user is not None and (is_admin or is_developer):
                django_login(request, user)
                session_manager.issue_session(request, user, device_info=request.META.get("HTTP_USER_AGENT", ""))
                if is_admin:
                    return redirect("moderation:dashboard")
                return redirect("portal:developer_dashboard")

            # Deliberately the same error for "wrong password" and "correct
            # password but not admin/developer" - don't leak which case it was.
            messages.error(request, "Invalid credentials or insufficient privileges for this portal.")
    else:
        form = LoginForm()
    return render(request, "moderation/portal_login.html", {"form": form})


@login_required
@developer_required
def developer_dashboard(request):
    """
    Owner: Mos. Mahabuba Akter Munia

    Raw database viewer for demonstrating to faculty that the encryption/
    hashing requirements are actually in effect - shows the literal column
    values Django/MySQL are storing, not a friendly formatted view. Once
    hashing (Afnan) and profile-data encryption (yours) are implemented for
    real, this page's output IS the demo: passwords should render as hash
    strings, encrypted_contact_info as ciphertext, not plaintext.

    TODO(Mos. Mahabuba Akter Munia):
        Extend this to show raw rows from other encrypted tables as they get
        built (crypto_core.KeyRecord, messaging.Message.ciphertext, private
        posts' encrypted_caption/encrypted_image_blob) so the demo covers
        every place data is supposed to be encrypted at rest, not just users.
    """
    users = User.objects.select_related("profile").all()
    return render(request, "moderation/developer_dashboard.html", {"users": users})


@login_required
@developer_required
def manage_admins(request):
    """
    Owner: Mos. Mahabuba Akter Munia

    REQUIREMENT: "Admins can only be created by Developer users... Whenever a
    new admin is created it will not be through a promotion system. A
    developer will create a new admin through registering them into the
    system." This is the ONLY place the Admin role can be granted - there is
    no more promote-a-user path (see moderation/views.py::user_management,
    which never had promote/demote buttons for exactly this reason). Also
    covers "developers... capable of creating/removing/banning admins":
    remove demotes an admin back to a Standard User, ban applies the same
    account-status cascade (friendship removal, session revocation) used
    elsewhere via apply_account_status_action. Scoped to Admin accounts only
    - Developer accounts aren't managed here.
    """
    if request.method == "POST" and request.POST.get("form") == "create_admin":
        create_form = AdminCreationForm(request.POST)
        if create_form.is_valid():
            new_admin = create_form.save(commit=False)
            # TODO(Afnan Satter): replace set_password with the from-scratch
            # hash+salt pipeline (accounts/security/hashing.py) instead of
            # Django's built-in hasher - same TODO as accounts/views.py::register.
            new_admin.set_password(create_form.cleaned_data["password"])
            new_admin.save()
            Profile.objects.create(user=new_admin, role=Role.ADMIN)
            TwoFactorSettings.objects.create(user=new_admin)
            log_event(request.user, "admin_created", target=new_admin)
            return redirect("portal:manage_admins")
    else:
        create_form = AdminCreationForm()

    if request.method == "POST" and request.POST.get("form") == "manage_admin":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"), profile__role=Role.ADMIN)
        action = request.POST.get("action")

        if action == "remove_admin":
            target_user.profile.role = Role.USER
            target_user.profile.save(update_fields=["role"])
            log_event(request.user, "admin_removed", target=target_user)
        elif action == "ban_admin":
            apply_account_status_action(request.user, target_user, "ban")

        return redirect("portal:manage_admins")

    accounts = User.objects.select_related("profile", "account_state").filter(profile__role=Role.ADMIN)
    return render(request, "moderation/manage_admins.html", {"accounts": accounts, "create_form": create_form})


@login_required
@developer_required
def manage_users(request):
    """
    Owner: Mos. Mahabuba Akter Munia

    The Developer-side counterpart to moderation/views.py::user_management -
    same lock/suspend/ban/reactivate/revoke_sessions actions (shared via
    apply_account_status_action), same Role.USER-only scoping, but reached
    through the developer panel rather than the admin panel. Kept as a
    separate view/URL from the admin one (not just a shared page) per the
    "two separate menus" requirement, even though the underlying action is
    identical.
    """
    if request.method == "POST":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"), profile__role=Role.USER)
        apply_account_status_action(request.user, target_user, request.POST.get("action"))
        return redirect("portal:manage_users")

    users = User.objects.select_related("profile", "account_state").filter(profile__role=Role.USER)
    return render(request, "moderation/manage_users.html", {"users": users})
