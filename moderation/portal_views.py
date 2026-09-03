"""
moderation/portal_views.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

The Developer panel: the raw-database viewer plus the two management menus
(manage_admins, manage_users).

LOGIN: there is no separate portal login any more. Everyone - Standard User,
Admin and Developer alike - signs in at the one shared /accounts/login/, and
accounts/views.py::login_view routes them to their own landing page using
moderation/permissions.py::home_url_for(). Each account holds exactly one
role, so that routing is unambiguous.

HIERARCHY (see moderation/permissions.py for the full writeup): Developers
manage the Admin role itself (manage_admins) and separately manage Standard
User accounts (manage_users) - two distinct menus. Admins can only manage
Standard User accounts (moderation/views.py::user_management) - they can't
create other admins or touch Developer accounts.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from accounts.models import Profile, Role, TwoFactorSettings
from crypto_core.models import KeyRecord
from messaging.models import Message
from posts.models import Post

from .forms import AdminCreationForm
from .logging_service import log_event
from .permissions import developer_required
from .views import apply_account_status_action

User = get_user_model()



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

    """
    users = User.objects.select_related("profile").all()
    return render(
        request,
        "moderation/developer_dashboard.html",
        {
            "users": users,
            "key_records": KeyRecord.objects.select_related("owner").all()[:200],
            "encrypted_messages": Message.objects.select_related("sender", "recipient").exclude(ciphertext="")[:200],
            "encrypted_posts": Post.objects.select_related("owner").exclude(encrypted_caption="")[:200],
        },
    )


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
            # Goes through FromScratchPasswordHasher, same as
            # accounts/views.py::register() - see accounts/security/hashing.py.
            new_admin.set_password(create_form.cleaned_data["password"])
            new_admin.save()
            Profile.objects.create(user=new_admin, role=Role.ADMIN)
            TwoFactorSettings.objects.create(user=new_admin)
            log_event(request.user, "admin_created", target=new_admin, request=request)
            return redirect("portal:manage_admins")
    else:
        create_form = AdminCreationForm()

    if request.method == "POST" and request.POST.get("form") == "manage_admin":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"), profile__role=Role.ADMIN)
        action = request.POST.get("action")

        if action == "remove_admin":
            target_user.profile.role = Role.USER
            target_user.profile.save(update_fields=["role"])
            log_event(request.user, "admin_removed", target=target_user, request=request)
        elif action == "ban_admin":
            apply_account_status_action(request.user, target_user, "ban")
            log_event(request.user, "admin_banned", target=target_user, request=request)

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
        action = request.POST.get("action")
        if apply_account_status_action(request.user, target_user, action):
            log_event(
                request.user,
                f"developer_account_{action}",
                target=target_user,
                request=request,
            )
        return redirect("portal:manage_users")

    users = User.objects.select_related("profile", "account_state").filter(profile__role=Role.USER)
    return render(request, "moderation/manage_users.html", {"users": users})
