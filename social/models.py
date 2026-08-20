"""
social/models.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)
"""

from django.conf import settings
from django.db import models

from posts.models import Post


class Like(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="likes")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="likes")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user", "post")

    def __str__(self):
        return f"Like({self.user.username} -> post {self.post_id})"


class Comment(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="comments")
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name="comments")

    content = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    is_deleted = models.BooleanField(default=False)  # admin moderation soft-delete

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Comment({self.user.username} on post {self.post_id})"
