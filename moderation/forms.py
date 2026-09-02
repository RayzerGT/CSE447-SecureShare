"""
moderation/forms.py
Owner: Mos. Mahabuba Akter Munia

REQUIREMENT: "Whenever a new admin is created it will not be through a
promotion system. A developer will create a new admin through registering
them into the system." This form is the registration-style equivalent of
accounts/forms.py::RegistrationForm, used only from the developer's
manage_admins() view (moderation/portal_views.py).
"""

from django import forms
from django.contrib.auth.models import User


class AdminCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ["username", "email"]

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("password") != cleaned.get("confirm_password"):
            raise forms.ValidationError("Passwords do not match.")
        return cleaned
