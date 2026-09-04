from django.conf import settings
from django.db import models

class Post(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="posts")

    image = models.ImageField(upload_to="posts/")
    caption = models.TextField(blank=True)

    encrypted_caption = models.TextField(blank=True)
    encrypted_image_blob = models.BinaryField(blank=True, null=True)
    encrypted_thumbnail_blob = models.BinaryField(blank=True, null=True)
    mac_tag = models.CharField(max_length=255, blank=True)
    caption_mac_tag = models.CharField(max_length=255, blank=True)

    is_flagged = models.BooleanField(default=False)
    is_deleted = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Post({self.owner.username}, #{self.pk})"
