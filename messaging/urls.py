from django.urls import path

from . import views

app_name = "messaging"

urlpatterns = [
    path("", views.inbox, name="inbox"),
    path("image/<int:message_id>/", views.message_image, name="message_image"),
    path("<str:username>/", views.thread, name="thread"),
]
