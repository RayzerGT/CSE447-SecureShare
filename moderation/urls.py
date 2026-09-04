from django.urls import path

from . import views

app_name = "moderation"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("audit-logs/", views.audit_logs, name="audit_logs"),
    path("users/", views.user_management, name="user_management"),
    path("content/", views.content_moderation, name="content_moderation"),
    path("post-image/<int:post_id>/", views.reported_post_image, name="reported_post_image"),
    path("reports/", views.reports_list, name="reports_list"),
    path("report/<int:post_id>/", views.submit_report, name="submit_report"),
    path("report-user/<str:username>/", views.report_user, name="report_user"),
    path("report-message/<int:message_id>/", views.report_message, name="report_message"),
    path("notice/<int:notice_id>/ack/", views.acknowledge_notice, name="acknowledge_notice"),
]
