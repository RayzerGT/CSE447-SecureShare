from django.apps import AppConfig


class ModerationConfig(AppConfig):
    """
    Split ownership - see todo.txt:
        - permissions.py (RBAC core + RoleAccessMiddleware), the admin
          dashboard shell (views.py::dashboard()), and portal_login()
          (portal_views.py)                                                  -> Razeen Hassan
        - audit log viewer, logging_service.py, user management (Standard
          Users only), content moderation, reports (the rest of views.py),
          plus the developer panel's developer_dashboard()/manage_admins()/
          manage_users() (portal_views.py)                                   -> Mos. Mahabuba Akter Munia

    This app now covers BOTH the admin panel (/moderation/) and the
    developer panel (/portal/, routed via portal_urls.py) - see
    moderation/permissions.py's HIERARCHY note for how those two are kept
    walled off from each other and from the regular social site.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "moderation"
