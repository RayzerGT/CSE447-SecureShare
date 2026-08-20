"""
messaging/models.py
Assigned to: Afnan Satter (see todo.txt)

REQUIREMENT (Idea.pdf): "Encrypted Direct Messaging (1-on-1 DMs)... Messages
will be encrypted at rest using the team's custom encryption scheme and key
management module."
"""

from django.conf import settings
from django.db import models


class Message(models.Model):
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="received_messages")

    # TODO(Afnan Satter): plaintext_body is a dev-only placeholder field so the
    # thread UI works before encryption is wired in. Once
    # crypto_core.encryption_service.encrypt_message/decrypt_message (Munia's
    # facade) are implemented, stop writing to plaintext_body and rely on
    # ciphertext + mac_tag only.
    plaintext_body = models.TextField(blank=True)

    ciphertext = models.TextField(blank=True)
    mac_tag = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Message({self.sender.username} -> {self.recipient.username})"
