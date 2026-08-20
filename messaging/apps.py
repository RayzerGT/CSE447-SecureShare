from django.apps import AppConfig


class MessagingConfig(AppConfig):
    """
    Assigned to: Afnan Satter (see todo.txt)

    Encrypted 1-on-1 direct messaging. Messages are encrypted at rest using
    crypto_core's custom encryption scheme (Mos. Mahabuba Akter Munia's
    encryption_service facade, built on Razeen's ECC) + key management module
    (Afnan's own KMM).
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "messaging"
