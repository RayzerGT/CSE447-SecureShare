from django.urls import path

from . import views

app_name = "social"

urlpatterns = [
    path("post/<int:post_id>/like/", views.like_post, name="like_post"),
    path("post/<int:post_id>/comment/", views.add_comment, name="add_comment"),
    path("comment/<int:comment_id>/delete/", views.delete_comment, name="delete_comment"),

    path("friends/", views.friends_list, name="friends_list"),
    path("search/", views.search_users, name="search_users"),
    path("friends/request/<str:username>/", views.send_friend_request, name="send_friend_request"),
    path("friends/accept/<int:request_id>/", views.accept_friend_request, name="accept_friend_request"),
    path("friends/reject/<int:request_id>/", views.reject_friend_request, name="reject_friend_request"),
    path("friends/remove/<str:username>/", views.remove_friend, name="remove_friend"),
]
