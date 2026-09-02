"""
social/models.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

Likes/comments plus the friends system: FriendRequest (pending) and
Friendship (accepted, symmetric). Only friends can message each other or
see each other's posts - see messaging/views.py and posts/views.py::feed().
"""

from django.conf import settings
from django.db import models
from django.db.models import Q

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


class FriendRequest(models.Model):
    """A pending friend request. Deleted on accept (replaced by a Friendship) or reject."""

    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="friend_requests_sent")
    receiver = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="friend_requests_received")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("sender", "receiver")
        ordering = ["-created_at"]

    def __str__(self):
        return f"FriendRequest({self.sender.username} -> {self.receiver.username})"


class Friendship(models.Model):
    """
    One row per accepted friendship. Symmetric - `user_a`/`user_b` are
    ordered by primary key (lower id first) on creation so there's never a
    duplicate reverse-direction row for the same pair.
    """

    user_a = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    user_b = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("user_a", "user_b")
        ordering = ["-created_at"]

    def __str__(self):
        return f"Friendship({self.user_a.username} <-> {self.user_b.username})"

    @staticmethod
    def create(user1, user2) -> "Friendship":
        a, b = sorted([user1, user2], key=lambda u: u.pk)
        friendship, _ = Friendship.objects.get_or_create(user_a=a, user_b=b)
        return friendship

    @staticmethod
    def are_friends(user1, user2) -> bool:
        if not (user1 and user2) or not (user1.is_authenticated and user2.is_authenticated):
            return False
        if user1.pk == user2.pk:
            return True  # a user can always see/message themselves
        a, b = sorted([user1, user2], key=lambda u: u.pk)
        return Friendship.objects.filter(user_a=a, user_b=b).exists()

    @staticmethod
    def friend_ids_of(user):
        """Every user id `user` is friends with (not including themselves)."""
        as_a = Friendship.objects.filter(user_a=user).values_list("user_b_id", flat=True)
        as_b = Friendship.objects.filter(user_b=user).values_list("user_a_id", flat=True)
        return set(as_a) | set(as_b)

    @staticmethod
    def remove_all_for(user) -> int:
        """
        REQUIREMENT: "A banned user will be completely removed from the
        friend lists of other users." Called from moderation's ban actions.
        Also implicitly hides the banned user's posts from everyone's feed,
        since posts/views.py::feed() only shows posts from friends.
        """
        qs = Friendship.objects.filter(Q(user_a=user) | Q(user_b=user))
        count = qs.count()
        qs.delete()
        FriendRequest.objects.filter(Q(sender=user) | Q(receiver=user)).delete()
        return count
