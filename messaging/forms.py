from django import forms


class MessageForm(forms.Form):
    body = forms.CharField(widget=forms.Textarea, label="", required=False)
    image = forms.ImageField(required=False)

    def clean(self):
        cleaned = super().clean()
        if not cleaned.get("body") and not cleaned.get("image"):
            raise forms.ValidationError("Write something or attach an image.")
        return cleaned
