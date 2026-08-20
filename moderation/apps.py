from django.apps import AppConfig


class ModerationConfig(AppConfig):
    """
    Split ownership - see todo.txt:
        - permissions.py (RBAC core) + the admin dashboard shell in views.py -> Razeen Hassan
        - audit log viewer, logging_service.py, user & role management,
          content moderation (the rest of views.py)                          -> Mos. Mahabuba Akter Munia
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "moderation"
