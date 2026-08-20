"""
posts/models.py
Assigned to: Afnan Satter (post creation/CRUD). Encryption of image/caption:
Mos. Mahabuba Akter Munia (posts/encryption.py). Visibility enforcement:
Mos. Mahabuba Akter Munia (posts/permissions.py).
"""

from django.conf import settings
from django.db import models


class Visibility(models.TextChoices):
    PUBLIC = "public", "Public"
    PRIVATE = "private", "Private"
    ROLE_RESTRICTED = "role_restricted", "Role-Restricted"


class Post(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="posts")

    image = models.ImageField(upload_to="posts/")
    caption = models.TextField(blank=True)

    # TODO(Mos. Mahabuba Akter Munia): once posts/encryption.py is implemented, the
    # plaintext `image`/`caption` fields above should hold/derive from ciphertext
    # for PRIVATE / ROLE_RESTRICTED posts. Keep a clear split between what's public
    # (may stay unencrypted per instructor's threat model) vs what must be encrypted.
    encrypted_caption = models.TextField(blank=True)
    encrypted_image_blob = models.BinaryField(blank=True, null=True)
    mac_tag = models.CharField(max_length=255, blank=True)

    visibility = models.CharField(max_length=20, choices=Visibility.choices, default=Visibility.PUBLIC)
    # TODO(Mos. Mahabuba Akter Munia): used when visibility == ROLE_RESTRICTED to decide who may view.
    allowed_role = models.CharField(max_length=16, blank=True, help_text="Role required when role-restricted.")

    is_flagged = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)  # moderation soft-delete (see moderation app)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Post({self.owner.username}, {self.visibility})"
