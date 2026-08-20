from django import forms


class MessageForm(forms.Form):
    body = forms.CharField(widget=forms.Textarea, label="")
