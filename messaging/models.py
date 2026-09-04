from django.conf import settings
from django.db import models

class Message(models.Model):
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="sent_messages")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="received_messages")

    plaintext_body = models.TextField(blank=True)

    image = models.ImageField(upload_to="messages/", blank=True, null=True)
    encrypted_image_blob = models.BinaryField(blank=True, null=True)
    image_mac_tag = models.CharField(max_length=255, blank=True)

    ciphertext = models.TextField(blank=True)
    mac_tag = models.CharField(max_length=255, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Message({self.sender.username} -> {self.recipient.username})"
