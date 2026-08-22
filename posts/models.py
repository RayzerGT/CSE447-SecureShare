"""
posts/models.py
Assigned to: Afnan Satter (post creation/CRUD). Encryption of image/caption:
Mos. Mahabuba Akter Munia (posts/encryption.py).

VISIBILITY: there is no per-post visibility setting. Every post is
friends-only, full stop - a post is visible to its owner and to that owner's
friends, and to nobody else. That single rule is enforced in posts/views.py
via social.models.Friendship, so there's no visibility column to keep in
sync and no separate permissions layer for posts.
"""

from django.conf import settings
from django.db import models


class Post(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="posts")

    image = models.ImageField(upload_to="posts/")
    caption = models.TextField(blank=True)

    # TODO(Mos. Mahabuba Akter Munia): once posts/encryption.py is implemented,
    # the plaintext `image`/`caption` fields above should hold/derive from
    # ciphertext. Since every post is friends-only now, this applies to all
    # posts - there's no "public" tier that could be left unencrypted.
    encrypted_caption = models.TextField(blank=True)
    encrypted_image_blob = models.BinaryField(blank=True, null=True)
    mac_tag = models.CharField(max_length=255, blank=True)

    is_flagged = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)  # moderation soft-delete (see moderation app)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Post({self.owner.username}, #{self.pk})"
