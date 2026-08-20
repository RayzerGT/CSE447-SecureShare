from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("django-admin/", admin.site.urls),  # Django's built-in admin (not the SecureShare admin panel)

    path("", include("posts.urls")),
    path("accounts/", include("accounts.urls")),
    path("messages/", include("messaging.urls")),
    path("social/", include("social.urls")),
    path("moderation/", include("moderation.urls")),
    path("portal/", include("moderation.portal_urls")),  # admin & developer login portal
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
