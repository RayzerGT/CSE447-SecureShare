"""
social/views.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

Likes/comments on posts, plus the friends system (search, requests,
friends list). Report submission (for posts/users/messages) lives in
moderation/views.py instead, so there's one place Report rows get created.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from posts.models import Post
from moderation.logging_service import log_event
from moderation.permissions import Permission, has_permission

from .models import Comment, Friendship, FriendRequest, Like
User = get_user_model()


@login_required
def like_post(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)
    like, created = Like.objects.get_or_create(user=request.user, post=post)
    if not created:
        like.delete()
        log_event(request.user, "post_unliked", target=post, request=request)
    else:
        log_event(request.user, "post_liked", target=post, request=request)
    return redirect("posts:detail", post_id=post.id)


@login_required
def add_comment(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)
    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        if content:
            comment = Comment.objects.create(user=request.user, post=post, content=content)
            log_event(request.user, "comment_created", target=comment, request=request)
    return redirect("posts:detail", post_id=post.id)


@login_required
def delete_comment(request, comment_id):
    """
    REQUIREMENT: "Admin users can delete inappropriate comments using their
    elevated privileges (RBAC)."
    Comment owners may remove their own comments; moderators need the
    centralized content-moderation permission.
    """
    comment = get_object_or_404(Comment, pk=comment_id)
    is_owner = comment.user_id == request.user.id
    can_moderate = has_permission(request.user, Permission.MODERATE_CONTENT)
    if is_owner or can_moderate:
        comment.is_deleted = True
        comment.save(update_fields=["is_deleted"])
        log_event(request.user, "comment_deleted", target=comment, request=request)
    return redirect("posts:detail", post_id=comment.post_id)


# ---------------------------------------------------------------------------
# Friends system
#
# REQUIREMENT: "Create a friends/following system. Only friends can message
# each other and view each others posts. Users can look for friends through
# searching." Fully functional (not a security stub) - this is an ordinary
# application feature, not one of the 12 CSE447 Project.pdf crypto/RBAC
# requirements. posts/views.py::feed() and messaging/views.py both gate on
# Friendship.are_friends() from here.
# ---------------------------------------------------------------------------

@login_required
def search_users(request):
    query = request.GET.get("q", "").strip()
    results = []
    if query:
        results = (
            User.objects.filter(username__icontains=query)
            .exclude(pk=request.user.pk)
            .select_related("profile")[:25]
        )

    friend_ids = Friendship.friend_ids_of(request.user)
    outgoing_ids = set(FriendRequest.objects.filter(sender=request.user).values_list("receiver_id", flat=True))
    incoming_ids = set(FriendRequest.objects.filter(receiver=request.user).values_list("sender_id", flat=True))

    rows = []
    for u in results:
        if u.id in friend_ids:
            status = "friends"
        elif u.id in outgoing_ids:
            status = "request_sent"
        elif u.id in incoming_ids:
            status = "request_received"
        else:
            status = "none"
        rows.append({"user": u, "status": status})

    return render(request, "social/search.html", {"query": query, "rows": rows})


@login_required
def send_friend_request(request, username):
    target = get_object_or_404(User, username=username)
    if request.method == "POST" and target.pk != request.user.pk:
        if not Friendship.are_friends(request.user, target):
            friend_request, created = FriendRequest.objects.get_or_create(sender=request.user, receiver=target)
            if created:
                log_event(
                    request.user,
                    "friend_request_sent",
                    target=target,
                    metadata={"request_id": friend_request.pk},
                    request=request,
                )
    return redirect(request.POST.get("next") or "social:search_users")


@login_required
def accept_friend_request(request, request_id):
    friend_request = get_object_or_404(FriendRequest, pk=request_id, receiver=request.user)
    if request.method == "POST":
        Friendship.create(friend_request.sender, friend_request.receiver)
        log_event(request.user, "friend_request_accepted", target=friend_request.sender, request=request)
        friend_request.delete()
    return redirect("social:friends_list")


@login_required
def reject_friend_request(request, request_id):
    friend_request = get_object_or_404(FriendRequest, pk=request_id, receiver=request.user)
    if request.method == "POST":
        log_event(request.user, "friend_request_rejected", target=friend_request.sender, request=request)
        friend_request.delete()
    return redirect("social:friends_list")


@login_required
def remove_friend(request, username):
    target = get_object_or_404(User, username=username)
    if request.method == "POST":
        a, b = sorted([request.user, target], key=lambda u: u.pk)
        deleted, _ = Friendship.objects.filter(user_a=a, user_b=b).delete()
        if deleted:
            log_event(request.user, "friend_removed", target=target, request=request)
    return redirect("social:friends_list")


@login_required
def friends_list(request):
    friend_ids = Friendship.friend_ids_of(request.user)
    friends = User.objects.filter(pk__in=friend_ids).select_related("profile")
    incoming = FriendRequest.objects.filter(receiver=request.user).select_related("sender")
    outgoing = FriendRequest.objects.filter(sender=request.user).select_related("receiver")
    return render(
        request,
        "social/friends_list.html",
        {"friends": friends, "incoming": incoming, "outgoing": outgoing},
    )
