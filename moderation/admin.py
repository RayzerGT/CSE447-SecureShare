from django.contrib import admin

from .models import AccountState, AuditLog, Report

admin.site.register(AuditLog)
admin.site.register(AccountState)
admin.site.register(Report)
