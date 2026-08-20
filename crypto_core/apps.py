from django.apps import AppConfig


class CryptoCoreConfig(AppConfig):
    """
    Home of the from-scratch cryptography required by the project. Jointly
    owned - see todo.txt in the project root for exact file-by-file
    ownership (short version: RSA + KMM = Afnan Satter, MAC + the
    encryption_service facade = Mos. Mahabuba Akter Munia; ECC lives in this
    app too but is implemented in accounts/../ecc_scratch.py by Razeen Hassan).

    Other apps call into this app via `encryption_service.py` rather than
    importing the raw primitives directly, so the rest of the team has a
    stable interface to build against.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "crypto_core"
