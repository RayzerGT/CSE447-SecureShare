from django.contrib import admin

from .models import AccountState, AuditLog

admin.site.register(AuditLog)
admin.site.register(AccountState)
