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
