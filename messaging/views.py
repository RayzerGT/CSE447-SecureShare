"""
messaging/views.py
Assigned to: Afnan Satter (see todo.txt)

TODO(Afnan Satter): wire crypto_core.encryption_service.EncryptionService.
encrypt_message / decrypt_message (Mos. Mahabuba Akter Munia's facade) +
MAC verify in send_message / thread below.

REQUIREMENT: "Only friends can message each other." The friend gate below
is fully implemented (functional feature, not one of the 12 CSE447
Project.pdf security items) using social.models.Friendship.
"""

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from crypto_core.encryption_service import EncryptionService
from moderation.logging_service import log_event
from social.models import Friendship

from .forms import MessageForm
from .models import Message

# TODO(Afnan Satter): from crypto_core.encryption_service import EncryptionService


def _conversation_list(user):
    """
    Every partner `user` has an open thread with, most-recent first, each
    paired with the latest message so the DM list can show a preview line
    (the two-pane inbox layout needs this on the thread page too, not just
    on /messages/).
    """
    conversations = (
        Message.objects.filter(Q(sender=user) | Q(recipient=user))
        .select_related("sender", "recipient", "sender__profile", "recipient__profile")
        .order_by("-created_at")
    )
    seen = set()
    threads = []
    for message in conversations:
        partner = message.recipient if message.sender_id == user.id else message.sender
        if partner.id not in seen:
            seen.add(partner.id)
            if message.ciphertext and message.mac_tag:
                try:
                    message.display_preview = EncryptionService.decrypt_message(
                        message.sender, message.recipient, message.ciphertext, message.mac_tag
                    )
                except ValueError:
                    message.display_preview = "[Integrity check failed]"
            else:
                message.display_preview = message.plaintext_body
            threads.append({"partner": partner, "last": message})
    return threads


@login_required
def inbox(request):
    return render(request, "messaging/inbox.html", {"threads": _conversation_list(request.user)})


@login_required
def thread(request, username):
    partner = get_object_or_404(User, username=username)

    if not Friendship.are_friends(request.user, partner):
        raise Http404("You can only message friends.")

    messages_qs = Message.objects.filter(
        Q(sender=request.user, recipient=partner) | Q(sender=partner, recipient=request.user)
    ).order_by("created_at")

    if request.method == "POST":
        form = MessageForm(request.POST, request.FILES)
        if form.is_valid():
            body = form.cleaned_data["body"]
            ciphertext, mac_tag = EncryptionService.encrypt_message(request.user, partner, body)
            Message.objects.create(
                sender=request.user,
                recipient=partner,
                ciphertext=ciphertext,
                mac_tag=mac_tag,
                image=form.cleaned_data.get("image"),
            )
            log_event(request.user, "message_sent", target=partner, request=request)
            return redirect("messaging:thread", username=partner.username)
    else:
        form = MessageForm()

    for message in messages_qs:
        if message.ciphertext and message.mac_tag:
            try:
                message.display_body = EncryptionService.decrypt_message(
                    message.sender,
                    message.recipient,
                    message.ciphertext,
                    message.mac_tag,
                )
            except ValueError:
                message.display_body = "[Message integrity check failed]"
        else:
            message.display_body = message.plaintext_body
    context = {
        # NOT "messages" - that key is owned by django.contrib.messages'
        # context processor, so using it here made every chat message render
        # as a flash banner in base.html.
        "thread_messages": messages_qs,
        "partner": partner,
        "form": form,
        "threads": _conversation_list(request.user),
    }
    return render(request, "messaging/thread.html", context)
