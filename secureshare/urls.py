from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("django-admin/", admin.site.urls),

    path("", include("posts.urls")),
    path("accounts/", include("accounts.urls")),
    path("messages/", include("messaging.urls")),
    path("social/", include("social.urls")),
    path("moderation/", include("moderation.urls")),
    path("portal/", include("moderation.portal_urls")),
]
