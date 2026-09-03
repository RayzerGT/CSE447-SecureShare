from django import forms
from django.contrib.auth.models import User

from .models import Profile, SecurityQuestion
from .security.two_factor import MIN_ANSWER_LENGTH, normalise_answer

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
    answer = forms.CharField(max_length=128, label="Your answer")


class SecurityQuestionForm(forms.Form):
    question = forms.ChoiceField(choices=SecurityQuestion.choices, label="Security question")
    answer = forms.CharField(max_length=128, label="Your answer")
    confirm_answer = forms.CharField(max_length=128, label="Confirm answer")

    def clean(self):
        cleaned = super().clean()
        answer = normalise_answer(cleaned.get("answer", ""))
        confirm = normalise_answer(cleaned.get("confirm_answer", ""))
        if answer and confirm and answer != confirm:
            raise forms.ValidationError("The two answers do not match.")
        if answer and len(answer) < MIN_ANSWER_LENGTH:
            raise forms.ValidationError(f"Your answer must be at least {MIN_ANSWER_LENGTH} characters.")
        return cleaned

class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ["full_name", "bio", "avatar"]
