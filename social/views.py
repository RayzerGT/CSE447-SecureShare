"""
social/views.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)
"""

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect

from posts.models import Post

from .models import Comment, Like

# TODO(Razeen Hassan): moderation.permissions has the RBAC core - import
# role_required/is_admin from there once it exists, instead of the naive
# owner-or-staff check below.
# TODO(Mos. Mahabuba Akter Munia): from moderation.logging_service import log_event


@login_required
def like_post(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)
    like, created = Like.objects.get_or_create(user=request.user, post=post)
    if not created:
        like.delete()
    return redirect("posts:detail", post_id=post.id)


@login_required
def add_comment(request, post_id):
    post = get_object_or_404(Post, pk=post_id, is_deleted=False)
    if request.method == "POST":
        content = request.POST.get("content", "").strip()
        if content:
            Comment.objects.create(user=request.user, post=post, content=content)
            # TODO(Mos. Mahabuba Akter Munia): log_event(actor=request.user, action="comment_created", target=post)
    return redirect("posts:detail", post_id=post.id)


@login_required
def delete_comment(request, comment_id):
    """
    REQUIREMENT: "Admin users can delete inappropriate comments using their
    elevated privileges (RBAC)."
    TODO(Mos. Mahabuba Akter Munia): replace the naive owner-or-staff check
    below with the real RBAC decision from moderation/permissions.py
    (Razeen Hassan's), and log the moderation action via
    moderation.logging_service.log_event.
    """
    comment = get_object_or_404(Comment, pk=comment_id)
    is_owner = comment.user_id == request.user.id
    is_admin = getattr(getattr(request.user, "profile", None), "is_admin", False)  # TODO(Mos. Mahabuba Akter Munia): use RBAC core instead
    if is_owner or is_admin:
        comment.is_deleted = True
        comment.save(update_fields=["is_deleted"])
    return redirect("posts:detail", post_id=comment.post_id)
