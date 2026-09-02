"""
posts/forms.py
Assigned to: Afnan Satter

No visibility field - every post is friends-only (see posts/models.py).
"""

from django import forms

from .models import Post


class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ["image", "caption"]
