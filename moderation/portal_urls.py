from django.urls import path

from . import portal_views

app_name = "portal"

urlpatterns = [
    path("login/", portal_views.portal_login, name="portal_login"),
    path("developer/", portal_views.developer_dashboard, name="developer_dashboard"),
    path("admins/", portal_views.manage_admins, name="manage_admins"),
    path("users/", portal_views.manage_users, name="manage_users"),
]
