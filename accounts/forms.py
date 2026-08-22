"""
accounts/forms.py
"""

from django import forms
from django.contrib.auth.models import User

from .models import Profile


class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    contact_info = forms.CharField(
        required=False,
        help_text="Stored encrypted at rest (TODO(Mos. Mahabuba Akter Munia): crypto_core wiring).",
    )

    class Meta:
        model = User
        fields = ["username", "email"]

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") != cleaned.get("confirm_password"):
            raise forms.ValidationError("Passwords do not match.")
        return cleaned


class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)


class TwoFactorForm(forms.Form):
    code = forms.CharField(max_length=6, label="Verification code")


class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ["full_name", "bio", "avatar"]
