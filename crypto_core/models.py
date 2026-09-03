from django.conf import settings
from django.db import models

class KeyRecord(models.Model):
    class Algorithm(models.TextChoices):
        RSA = "rsa", "RSA (from scratch)"
        ECC = "ecc", "ECC (from scratch)"

    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="key_records")
    algorithm = models.CharField(max_length=8, choices=Algorithm.choices)

    public_key = models.TextField(blank=True)

    encrypted_private_key = models.TextField(blank=True)

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    rotated_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"KeyRecord({self.owner.username}, {self.algorithm}, active={self.is_active})"
