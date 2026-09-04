from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.db.models import Count, Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from social.models import Friendship, Like

from .encryption import (
    ENCRYPTED_BLOB_FIELDS,
    decrypt_caption,
    decrypt_image,
    encrypt_and_store,
    seal_caption,
)
from .forms import PostForm
from .imaging import CONTENT_TYPE, prepare_upload
from .models import Post


def _visible_to(user, post) -> bool:
    return post.owner_id == user.id or Friendship.are_friends(user, post.owner)


@login_required
def feed(request):
    friend_ids = Friendship.friend_ids_of(request.user)
    posts = (
        Post.objects.filter(is_deleted=False)
        .filter(Q(owner=request.user) | Q(owner_id__in=friend_ids))
        .defer(*ENCRYPTED_BLOB_FIELDS)
        .select_related("owner", "owner__profile")
        .prefetch_related("comments__user")
        .annotate(
            like_count=Count("likes", distinct=True),
            comment_count=Count("comments", filter=Q(comments__is_deleted=False), distinct=True),
        )
    )
    for post in posts:
        post.display_caption = decrypt_caption(post)

    context = {
        "posts": posts,
        "liked_post_ids": set(
            Like.objects.filter(user=request.user, post__in=posts).values_list("post_id", flat=True)
        ),
        "friends": User.objects.filter(pk__in=friend_ids).select_related("profile")[:16],
    }
    return render(request, "posts/feed.html", context)


@login_required
def post_image(request, post_id):
    return _serve_image(request, post_id, thumbnail=False)


@login_required
def post_thumbnail(request, post_id):
    return _serve_image(request, post_id, thumbnail=True)


def _serve_image(request, post_id, thumbnail: bool):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)
    if not _visible_to(request.user, post):
        raise Http404("Post not found or not visible to you.")

    image_bytes = decrypt_image(post, prefer_thumbnail=thumbnail)
    response = HttpResponse(image_bytes, content_type=CONTENT_TYPE)
    response["Cache-Control"] = "private, max-age=86400"
    response["Content-Length"] = str(len(image_bytes))
    return response


@login_required
def upload(request):
    if request.method == "POST":
        form = PostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.owner = request.user
            uploaded_image = form.cleaned_data["image"]
            full_image, thumbnail = prepare_upload(uploaded_image.read())
            post.image = uploaded_image.name
            encrypt_and_store(post, full_image, form.cleaned_data["caption"], thumbnail)
            post.save()
            seal_caption(post)
            post.save(
                update_fields=[
                    "image",
                    "caption",
                    "encrypted_image_blob",
                    "encrypted_thumbnail_blob",
                    "encrypted_caption",
                    "mac_tag",
                    "caption_mac_tag",
                ]
            )

            return redirect("posts:feed")
    else:
        form = PostForm()
    return render(request, "posts/upload.html", {"form": form})


@login_required
def detail(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)

    if not _visible_to(request.user, post):
        raise Http404("Post not found or not visible to you.")

    post.display_caption = decrypt_caption(post)
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
            uploaded_image = request.FILES.get("image")
            if uploaded_image:
                full_image, thumbnail = prepare_upload(uploaded_image.read())
            else:
                full_image, thumbnail = prepare_upload(decrypt_image(post))
            encrypt_and_store(post, full_image, form.cleaned_data["caption"], thumbnail)
            seal_caption(post)
            post.save(
                update_fields=[
                    "caption",
                    "encrypted_image_blob",
                    "encrypted_thumbnail_blob",
                    "encrypted_caption",
                    "mac_tag",
                    "caption_mac_tag",
                ]
            )
            if uploaded_image:
                post.image = uploaded_image.name
                post.save(update_fields=["image"])
            return redirect("posts:detail", post_id=post.id)
    else:
        form = PostForm(instance=post)
    return render(request, "posts/upload.html", {"form": form, "editing": True})
