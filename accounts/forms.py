"""
accounts/forms.py
"""

from django import forms
from django.contrib.auth.models import User

from .models import Profile


class RegistrationForm(forms.ModelForm):
    first_name = forms.CharField(max_length=75)
    last_name = forms.CharField(max_length=75)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    contact_info = forms.CharField(
        required=False,
        help_text="Stored encrypted at rest.",
    )

    class Meta:
        model = User
        fields = ["username", "email", "first_name", "last_name"]

    def __init__(self, *args, google_signup=False, **kwargs):
        # google_signup=True means the visitor already authenticated with
        # Google (accounts/views.py::google_login_callback) and is only
        # here to finish account creation - see google_oauth.py for why
        # that's trusted. No local password to collect in that case, and
        # the email is locked to whatever Google verified so the account
        # stays reachable via "Sign in with Google" afterwards.
        self.google_signup = google_signup
        super().__init__(*args, **kwargs)
        if google_signup:
            del self.fields["password"]
            del self.fields["confirm_password"]
            self.fields["email"].disabled = True

    def clean(self):
        cleaned = super().clean()
        if not self.google_signup and cleaned.get("password") != cleaned.get("confirm_password"):
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
