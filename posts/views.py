"""
posts/views.py
Assigned to: Afnan Satter (post creation - feed/upload/detail/edit CRUD).
Security wiring point marked inline:
    - Mos. Mahabuba Akter Munia: posts/encryption.py (encrypt_and_store / decrypt_for_display)

VISIBILITY RULE (the only one): a post is visible to its owner and to that
owner's friends. Nothing else. There is no public/private/role-restricted
setting and no posts/permissions.py layer - the friends check below IS the
whole rule, and it's ordinary application logic, not one of the 12 CSE447
Project.pdf security items.
"""

from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from social.models import Friendship, Like

from .forms import PostForm
from .models import Post

# TODO(Mos. Mahabuba Akter Munia): from .encryption import encrypt_and_store, decrypt_for_display


@login_required
def feed(request):
    friend_ids = Friendship.friend_ids_of(request.user)
    posts = (
        Post.objects.filter(is_deleted=False)
        .filter(Q(owner=request.user) | Q(owner_id__in=friend_ids))
        .select_related("owner", "owner__profile")
        .prefetch_related("comments__user")
        .annotate(
            like_count=Count("likes", distinct=True),
            comment_count=Count("comments", filter=Q(comments__is_deleted=False), distinct=True),
        )
    )

    context = {
        "posts": posts,
        # Which of these posts the viewer has already liked, so the heart
        # renders filled (UI state only - no permission meaning).
        "liked_post_ids": set(
            Like.objects.filter(user=request.user, post__in=posts).values_list("post_id", flat=True)
        ),
        # Friends strip across the top of the feed (Instagram's story rail).
        "friends": User.objects.filter(pk__in=friend_ids).select_related("profile")[:16],
    }
    return render(request, "posts/feed.html", context)


@login_required
def upload(request):
    if request.method == "POST":
        form = PostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.owner = request.user

            # TODO(Mos. Mahabuba Akter Munia): call encrypt_and_store(post,
            # image_bytes, caption) here instead of saving the plaintext
            # image/caption directly.
            post.save()

            return redirect("posts:feed")
    else:
        form = PostForm()
    return render(request, "posts/upload.html", {"form": form})


@login_required
def detail(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)

    if post.owner_id != request.user.id and not Friendship.are_friends(request.user, post.owner):
        raise Http404("Post not found or not visible to you.")

    # TODO(Mos. Mahabuba Akter Munia): call decrypt_for_display(post) to get
    # the plaintext image/caption for rendering.
    context = {
        "post": post,
        "comments": post.comments.filter(is_deleted=False).select_related("user", "user__profile"),
        "like_count": post.likes.count(),
        "is_liked": post.likes.filter(user=request.user).exists(),
    }
    return render(request, "posts/detail.html", context)


@login_required
def edit(request, post_id):
    post = get_object_or_404(Post, pk=post_id, owner=request.user, is_deleted=False)
    if request.method == "POST":
        form = PostForm(request.POST, request.FILES, instance=post)
        if form.is_valid():
            # TODO(Mos. Mahabuba Akter Munia): re-encrypt on edit if needed.
            form.save()
            return redirect("posts:detail", post_id=post.id)
    else:
        form = PostForm(instance=post)
    return render(request, "posts/upload.html", {"form": form, "editing": True})
