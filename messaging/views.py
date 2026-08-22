"""
messaging/views.py
Assigned to: Afnan Satter (see todo.txt)

TODO(Afnan Satter): wire crypto_core.encryption_service.EncryptionService.
encrypt_message / decrypt_message (Mos. Mahabuba Akter Munia's facade) +
MAC verify in send_message / thread below.
"""

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from .forms import MessageForm
from .models import Message

# TODO(Afnan Satter): from crypto_core.encryption_service import EncryptionService


@login_required
def inbox(request):
    conversations = (
        Message.objects.filter(Q(sender=request.user) | Q(recipient=request.user))
        .order_by("-created_at")
    )
    partner_ids = set()
    threads = []
    for message in conversations:
        partner = message.recipient if message.sender_id == request.user.id else message.sender
        if partner.id not in partner_ids:
            partner_ids.add(partner.id)
            threads.append(partner)
    return render(request, "messaging/inbox.html", {"threads": threads})


@login_required
def thread(request, username):
    partner = get_object_or_404(User, username=username)
    messages_qs = Message.objects.filter(
        Q(sender=request.user, recipient=partner) | Q(sender=partner, recipient=request.user)
    ).order_by("created_at")

    if request.method == "POST":
        form = MessageForm(request.POST)
        if form.is_valid():
            # TODO(Afnan Satter): replace plaintext_body write with
            # ciphertext, mac_tag = EncryptionService.encrypt_message(request.user, partner, body)
            Message.objects.create(
                sender=request.user,
                recipient=partner,
                plaintext_body=form.cleaned_data["body"],
            )
            return redirect("messaging:thread", username=partner.username)
    else:
        form = MessageForm()

    # TODO(Afnan Satter): decrypt each message's ciphertext (after MAC
    # verification) for display instead of reading plaintext_body directly.
    return render(request, "messaging/thread.html", {"partner": partner, "messages": messages_qs, "form": form})
