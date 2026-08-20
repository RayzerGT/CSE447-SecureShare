from django.apps import AppConfig


class AccountsConfig(AppConfig):
    """
    User onboarding & authentication, password hashing/salting, 2FA,
    secure session management, and the user security/account dashboard.
    This app is jointly owned - see todo.txt in the project root for which
    files/functions belong to which teammate.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"
