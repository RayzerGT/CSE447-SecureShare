"""
crypto_core/encryption_service.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

Facade used by every other app (accounts, posts, messaging) so they never
have to import rsa_scratch/ecc_scratch/kmm/hmac_scratch directly. This is
the main integration point: keep the function signatures stable so the
other apps' call sites (already marked with matching TODOs in
accounts/models.py, accounts/views.py, accounts/forms.py, posts/, and
messaging/) don't need to change once the real crypto lands.

REQUIREMENT recap (CSE447 Project.pdf):
    - Exclusively asymmetric encryption, at least 2 different algorithms,
      each used for a different part of the system (Afnan's RSA, Razeen's
      ECC - split however makes sense, just don't use a single algorithm for
      everything).
    - All critical data (user info, posts, keys) stored encrypted, MAC'd
      for integrity (your own hmac_scratch.py).

TODO(Mos. Mahabuba Akter Munia):
    Implement each method by delegating to RSACipher / ECCCipher
    (asymmetric/, owned by Afnan and Razeen respectively) +
    KeyManagementModule (key_management/kmm.py, Afnan's) + compute_mac/
    verify_mac (mac/hmac_scratch.py, yours). Suggested split so both
    required algorithms are actually exercised:
        - encrypt_profile_data / decrypt_profile_data -> RSA (Afnan's)
        - encrypt_message / decrypt_message            -> ECC (Razeen's)
        - encrypt_post / decrypt_post                  -> either, document choice
"""


class EncryptionService:
    @staticmethod
    def encrypt_profile_data(user, plaintext: str) -> str:
        raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): encrypt profile fields (suggest: RSA).")

    @staticmethod
    def decrypt_profile_data(user, ciphertext: str) -> str:
        raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): decrypt profile fields.")

    @staticmethod
    def encrypt_message(sender, recipient, plaintext: str) -> tuple:
        """Should return (ciphertext, mac_tag)."""
        raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): encrypt + MAC a DM (suggest: ECC).")

    @staticmethod
    def decrypt_message(sender, recipient, ciphertext: str, mac_tag: str) -> str:
        raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): verify MAC then decrypt a DM.")

    @staticmethod
    def encrypt_post(owner, image_bytes: bytes, caption: str) -> tuple:
        """Should return (encrypted_image_bytes, encrypted_caption)."""
        raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): encrypt private post image + caption.")

    @staticmethod
    def decrypt_post(owner, encrypted_image_bytes: bytes, encrypted_caption: str) -> tuple:
        raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): decrypt private post image + caption.")
