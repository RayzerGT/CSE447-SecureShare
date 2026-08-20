from django.apps import AppConfig


class PostsConfig(AppConfig):
    """
    Shared app - see todo.txt for exact ownership:
        - models.py, forms.py, views.py, urls.py, templates/ (creation/feed/
          upload/edit CRUD) -> Afnan Satter
        - encryption.py (image/caption encryption)                -> Mos. Mahabuba Akter Munia
        - permissions.py (visibility/RBAC enforcement)             -> Mos. Mahabuba Akter Munia
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "posts"
