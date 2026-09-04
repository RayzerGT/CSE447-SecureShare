from django.urls import path

from . import views

app_name = "posts"

urlpatterns = [
    path("", views.feed, name="feed"),
    path("upload/", views.upload, name="upload"),
    path("post/<int:post_id>/", views.detail, name="detail"),
    path("post/<int:post_id>/edit/", views.edit, name="edit"),
    path("post/<int:post_id>/image/", views.post_image, name="image"),
    path("post/<int:post_id>/thumb/", views.post_thumbnail, name="thumbnail"),
]
