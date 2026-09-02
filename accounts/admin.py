from django.contrib import admin

from .models import ActiveSession, Profile, TwoFactorSettings

admin.site.register(Profile)
admin.site.register(TwoFactorSettings)
admin.site.register(ActiveSession)
