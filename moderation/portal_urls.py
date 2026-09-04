from django.urls import path

from . import portal_views

app_name = "portal"

urlpatterns = [
    path("developer/", portal_views.developer_dashboard, name="developer_dashboard"),
    path("developer/rotate-key/", portal_views.rotate_key, name="rotate_key"),
    path("admins/", portal_views.manage_admins, name="manage_admins"),
    path("users/", portal_views.manage_users, name="manage_users"),
]
