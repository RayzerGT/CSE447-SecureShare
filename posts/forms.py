"""
posts/forms.py
Assigned to: Afnan Satter
"""

from django import forms

from .models import Post


class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ["image", "caption", "visibility", "allowed_role"]
