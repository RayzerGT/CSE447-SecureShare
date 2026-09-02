from django.apps import AppConfig


class CryptoCoreConfig(AppConfig):
    """
    Home of the from-scratch cryptography required by the project. Jointly
    owned - see todo.txt in the project root for exact file-by-file
    ownership (short version: RSA (asymmetric/rsa_scratch.py) + KMM
    (key_management/kmm.py) + models.py = Afnan Satter; MAC (mac/hmac_scratch.py)
    + the encryption_service.py facade = Mos. Mahabuba Akter Munia; ECC
    (asymmetric/ecc_scratch.py) = Razeen Hassan).

    Other apps call into this app via `encryption_service.py` rather than
    importing the raw primitives directly, so the rest of the team has a
    stable interface to build against.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "crypto_core"
