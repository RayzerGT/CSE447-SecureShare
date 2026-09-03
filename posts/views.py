from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
import base64
import mimetypes

from social.models import Friendship, Like

from .forms import PostForm
from .models import Post
from .encryption import decrypt_for_display, encrypt_and_store

def _decrypt_post_for_template(post):
    image_bytes, caption = decrypt_for_display(post)
    content_type = mimetypes.guess_type(post.image.name if post.image else "")[0] or "application/octet-stream"
    post.display_image = f"data:{content_type};base64,{base64.b64encode(image_bytes).decode('ascii')}"
    post.display_caption = caption
    return post

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
    for post in posts:
        _decrypt_post_for_template(post)

    context = {
        "posts": posts,
        "liked_post_ids": set(
            Like.objects.filter(user=request.user, post__in=posts).values_list("post_id", flat=True)
        ),
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
            uploaded_image = form.cleaned_data["image"]
            image_bytes = uploaded_image.read()
            encrypt_and_store(post, image_bytes, form.cleaned_data["caption"])
            post.save()
            image_name = post.image.name
            post.image.delete(save=False)
            post.image.name = image_name
            post.save(update_fields=["image", "caption", "encrypted_image_blob", "encrypted_caption", "mac_tag"])

            return redirect("posts:feed")
    else:
        form = PostForm()
    return render(request, "posts/upload.html", {"form": form})

@login_required
def detail(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)

    if post.owner_id != request.user.id and not Friendship.are_friends(request.user, post.owner):
        raise Http404("Post not found or not visible to you.")

    _decrypt_post_for_template(post)
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
            old_image, _ = decrypt_for_display(post)
            uploaded_image = form.cleaned_data.get("image")
            image_bytes = uploaded_image.read() if uploaded_image else old_image
            encrypt_and_store(post, image_bytes, form.cleaned_data["caption"])
            post.save(update_fields=["caption", "encrypted_image_blob", "encrypted_caption", "mac_tag"])
            if uploaded_image:
                image_name = uploaded_image.name
                post.image.delete(save=False)
                post.image.name = image_name
                post.save(update_fields=["image"])
            return redirect("posts:detail", post_id=post.id)
    else:
        form = PostForm(instance=post)
    return render(request, "posts/upload.html", {"form": form, "editing": True})
