from django.urls import path

from . import views

app_name = "moderation"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("audit-logs/", views.audit_logs, name="audit_logs"),
    path("users/", views.user_management, name="user_management"),
    path("content/", views.content_moderation, name="content_moderation"),
]
