from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from accounts.models import Profile, Role, TwoFactorSettings
from crypto_core.encryption_service import EncryptionService
from crypto_core.key_management.kmm import KeyManagementModule
from crypto_core.models import KeyRecord
from messaging.models import Message
from posts.encryption import decrypt_for_display
from posts.models import Post

from .forms import AdminCreationForm
from .logging_service import log_event
from .models import AccountState
from .permissions import Permission, developer_required, require_permission
from .moderation_service import apply_account_status_action

User = get_user_model()


def _verify_pre_rotation_data(target):
    profile = getattr(target, "profile", None)
    if profile is not None and profile.encrypted_contact_info:
        try:
            EncryptionService.decrypt_profile_data(target, profile.encrypted_contact_info)
            return True, "contact info encrypted before the rotation still decrypts"
        except Exception as exc:
            return False, f"contact info could NOT be decrypted after rotation ({type(exc).__name__})"

    post = Post.objects.filter(owner=target).exclude(encrypted_caption="").first()
    if post is not None:
        try:
            decrypt_for_display(post)
            return True, f"post #{post.pk} encrypted before the rotation still decrypts"
        except Exception as exc:
            return False, f"post #{post.pk} could NOT be decrypted after rotation ({type(exc).__name__})"

    message = Message.objects.filter(recipient=target).exclude(ciphertext="").first()
    if message is not None:
        try:
            EncryptionService.decrypt_message(
                message.sender, message.recipient, message.ciphertext, message.mac_tag
            )
            return True, f"message #{message.pk} encrypted before the rotation still decrypts"
        except Exception as exc:
            return False, f"message #{message.pk} could NOT be decrypted after rotation ({type(exc).__name__})"

    return None, "this account has no encrypted data yet, so there was nothing to re-check"

@login_required
@developer_required
@require_permission(Permission.ROTATE_KEYS)
def rotate_key(request):
    if request.method != "POST":
        return redirect("portal:developer_dashboard")

    target = get_object_or_404(User, pk=request.POST.get("user_id"))
    algorithm = request.POST.get("algorithm")
    if algorithm not in (KeyRecord.Algorithm.RSA, KeyRecord.Algorithm.ECC):
        messages.error(request, "Unknown key algorithm.")
        return redirect("portal:developer_dashboard")

    previous = KeyRecord.objects.filter(owner=target, algorithm=algorithm, is_active=True).first()
    previous_id = previous.pk if previous else None

    replacement = KeyManagementModule.generate_key_for_user(target, algorithm)
    still_readable, detail = _verify_pre_rotation_data(target)

    log_event(
        request.user,
        "key_rotated",
        target=target,
        metadata={
            "algorithm": algorithm,
            "previous_key": previous_id,
            "new_key": replacement.pk,
            "old_data_readable": still_readable,
        },
        request=request,
    )

    headline = (
        f"Rotated {algorithm.upper()} key for {target.username}: "
        f"#{previous_id} retired, #{replacement.pk} now active."
    )
    if still_readable is False:
        messages.error(request, f"{headline} WARNING - {detail}.", extra_tags="sticky")
    else:
        messages.success(request, f"{headline} Verified: {detail}.", extra_tags="sticky")

    return redirect("portal:developer_dashboard")


@login_required
@developer_required
def developer_dashboard(request):
    users = User.objects.select_related("profile").all()
    return render(
        request,
        "moderation/developer_dashboard.html",
        {
            "users": users,
            "key_records": KeyRecord.objects.select_related("owner").order_by(
                "owner__username", "algorithm", "-is_active", "-created_at"
            )[:200],
            "encrypted_messages": Message.objects.select_related("sender", "recipient").exclude(ciphertext="")[:200],
            "encrypted_posts": Post.objects.select_related("owner").exclude(encrypted_caption="")[:200],
        },
    )

@login_required
@developer_required
def manage_admins(request):
    if request.method == "POST" and request.POST.get("form") == "create_admin":
        create_form = AdminCreationForm(request.POST)
        if create_form.is_valid():
            new_admin = create_form.save(commit=False)
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
    if request.method == "POST":
        target_user = get_object_or_404(User, pk=request.POST.get("user_id"), profile__role=Role.USER)
        action = request.POST.get("action")
        reason = request.POST.get("reason", "").strip()
        days = request.POST.get("days")
        if apply_account_status_action(
            request.user, target_user, action, reason, int(days) if days and days.isdigit() else None
        ):
            log_event(
                request.user,
                f"developer_account_{action}",
                target=target_user,
                request=request,
            )
        return redirect("portal:manage_users")

    users = User.objects.select_related("profile", "account_state").filter(profile__role=Role.USER)
    return render(
        request,
        "moderation/manage_users.html",
        {
            "users": users,
            "suspension_days": AccountState.DEFAULT_SUSPENSION_DAYS,
            "warnings_before_suspension": AccountState.WARNINGS_BEFORE_SUSPENSION,
        },
    )
