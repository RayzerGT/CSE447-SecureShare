from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("verify-2fa/", views.verify_2fa, name="verify_2fa"),
    path("logout/", views.logout_view, name="logout"),
    path("profile/", views.profile_view, name="profile"),
    path("profile/edit/", views.profile_edit, name="profile_edit"),
    path("profile/<str:username>/", views.profile_view, name="profile_detail"),
    path("sessions/", views.sessions_dashboard, name="sessions"),
]
