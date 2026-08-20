"""
posts/views.py
Assigned to: Afnan Satter (post creation - feed/upload/detail/edit CRUD).
Security wiring points are marked inline:
    - Mos. Mahabuba Akter Munia: posts/encryption.py (encrypt_and_store / decrypt_for_display)
    - Mos. Mahabuba Akter Munia: posts/permissions.py (can_view_post / visible_posts_queryset)
"""

from django.contrib.auth.decorators import login_required
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render

from .forms import PostForm
from .models import Post
from .permissions import can_view_post, visible_posts_queryset

# TODO(Mos. Mahabuba Akter Munia): from .encryption import encrypt_and_store, decrypt_for_display


@login_required
def feed(request):
    queryset = Post.objects.filter(is_deleted=False)
    # TODO(Mos. Mahabuba Akter Munia): replace with real RBAC/visibility filtering.
    queryset = visible_posts_queryset(request.user, queryset)
    return render(request, "posts/feed.html", {"posts": queryset})


@login_required
def upload(request):
    if request.method == "POST":
        form = PostForm(request.POST, request.FILES)
        if form.is_valid():
            post = form.save(commit=False)
            post.owner = request.user

            # TODO(Mos. Mahabuba Akter Munia): for PRIVATE/ROLE_RESTRICTED posts,
            # call encrypt_and_store(post, image_bytes, caption) here instead of
            # saving the plaintext image/caption directly.
            post.save()

            return redirect("posts:feed")
    else:
        form = PostForm()
    return render(request, "posts/upload.html", {"form": form})


@login_required
def detail(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)

    # TODO(Mos. Mahabuba Akter Munia): replace with real RBAC/visibility enforcement (403 vs 404).
    if not can_view_post(request.user, post):
        raise Http404("Post not found or not visible to you.")

    # TODO(Mos. Mahabuba Akter Munia): if post.visibility != PUBLIC, call
    # decrypt_for_display(post) to get plaintext image/caption for rendering.
    return render(request, "posts/detail.html", {"post": post})


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
