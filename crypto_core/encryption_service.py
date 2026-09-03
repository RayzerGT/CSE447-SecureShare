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

import base64
import json

from django.conf import settings

from crypto_core.asymmetric.ecc_scratch import ECCCipher
from crypto_core.asymmetric.rsa_scratch import RSACipher
from crypto_core.key_management.kmm import KeyManagementModule
from crypto_core.mac.hmac_scratch import compute_mac, verify_mac
from crypto_core.models import KeyRecord


class EncryptionService:
    @staticmethod
    def _key_record(user, algorithm: str) -> KeyRecord:
        try:
            return KeyManagementModule.get_active_key_for_user(user, algorithm)
        except KeyRecord.DoesNotExist:
            return KeyManagementModule.generate_key_for_user(user, algorithm)

    @staticmethod
    def _public_key(record: KeyRecord):
        values = json.loads(record.public_key)
        if record.algorithm == KeyRecord.Algorithm.RSA:
            return values["e"], values["n"]
        if record.algorithm == KeyRecord.Algorithm.ECC:
            return values["x"], values["y"]
        raise ValueError(f"unknown key algorithm: {record.algorithm}")

    @staticmethod
    def _mac_root_secret() -> bytes:
        """
        The secret a MAC key is derived from. KMM_MASTER_KEY is the project's
        crypto root of trust (see crypto_core/key_management/master_key.py);
        SECRET_KEY is the fallback so this still works on a checkout that
        hasn't set one yet. Both live in .env, never in the database - which
        is the whole point (see _mac_key).
        """
        root = getattr(settings, "KMM_MASTER_KEY", "") or settings.SECRET_KEY
        return str(root).encode("utf-8")

    @staticmethod
    def _mac_key(sender, recipient) -> bytes:
        """
        Per-conversation MAC key, derived from a SECRET root.

        This must not be built out of public values. An earlier version used
        `sender.pk : recipient.pk : <public key>`, all of which is readable
        straight from the database - so anyone who could tamper with stored
        ciphertext could also recompute a matching tag, and the MAC proved
        nothing. (Verified at the time: a fabricated message forged that way
        passed verification.) The requirement is to "detect unauthorized
        modifications" under a database-compromise threat model, so the key
        has to be something the database does not contain.

        Deriving it as HMAC(context, root_secret) keeps the per-pair
        separation the old version had, while making the key unforgeable
        without the root secret from .env.
        """
        context = f"secureshare-dm-mac:{sender.pk}:{recipient.pk}".encode("utf-8")
        return compute_mac(context, EncryptionService._mac_root_secret())

    @staticmethod
    def _rsa_encrypt_chunks(plaintext: bytes, public_key: tuple) -> bytes:
        _, modulus = public_key
        block_size = (modulus.bit_length() + 7) // 8 - 11
        if not plaintext:
            return RSACipher.encrypt(b"", public_key)
        return b"".join(
            RSACipher.encrypt(plaintext[index:index + block_size], public_key)
            for index in range(0, len(plaintext), block_size)
        )

    @staticmethod
    def _rsa_decrypt_chunks(ciphertext: bytes, private_key: tuple) -> bytes:
        _, modulus = private_key
        block_size = (modulus.bit_length() + 7) // 8
        if not ciphertext or len(ciphertext) % block_size:
            raise ValueError("malformed RSA ciphertext")
        return b"".join(
            RSACipher.decrypt(ciphertext[index:index + block_size], private_key)
            for index in range(0, len(ciphertext), block_size)
        )

    @staticmethod
    def encrypt_profile_data(user, plaintext: str) -> str:
        record = EncryptionService._key_record(user, KeyRecord.Algorithm.RSA)
        ciphertext = EncryptionService._rsa_encrypt_chunks(
            plaintext.encode("utf-8"), EncryptionService._public_key(record)
        )
        return base64.b64encode(ciphertext).decode("ascii")

    @staticmethod
    def decrypt_profile_data(user, ciphertext: str) -> str:
        record = EncryptionService._key_record(user, KeyRecord.Algorithm.RSA)
        plaintext = EncryptionService._rsa_decrypt_chunks(
            base64.b64decode(ciphertext, validate=True),
            KeyManagementModule.get_private_key(record),
        )
        return plaintext.decode("utf-8")

    @staticmethod
    def encrypt_message(sender, recipient, plaintext: str) -> tuple:
        """Should return (ciphertext, mac_tag)."""
        record = EncryptionService._key_record(recipient, KeyRecord.Algorithm.ECC)
        ciphertext = ECCCipher.encrypt(plaintext.encode("utf-8"), EncryptionService._public_key(record))
        mac_tag = compute_mac(ciphertext, EncryptionService._mac_key(sender, recipient)).hex()
        return base64.b64encode(ciphertext).decode("ascii"), mac_tag

    @staticmethod
    def decrypt_message(sender, recipient, ciphertext: str, mac_tag: str) -> str:
        raw_ciphertext = base64.b64decode(ciphertext, validate=True)
        if not verify_mac(raw_ciphertext, EncryptionService._mac_key(sender, recipient), mac_tag):
            raise ValueError("message MAC verification failed")
        record = EncryptionService._key_record(recipient, KeyRecord.Algorithm.ECC)
        plaintext = ECCCipher.decrypt(raw_ciphertext, KeyManagementModule.get_private_key(record))
        return plaintext.decode("utf-8")

    @staticmethod
    def encrypt_post(owner, image_bytes: bytes, caption: str) -> tuple:
        """Should return (encrypted_image_bytes, encrypted_caption)."""
        record = EncryptionService._key_record(owner, KeyRecord.Algorithm.RSA)
        public_key = EncryptionService._public_key(record)
        encrypted_image = EncryptionService._rsa_encrypt_chunks(image_bytes, public_key)
        encrypted_caption = base64.b64encode(
            EncryptionService._rsa_encrypt_chunks(caption.encode("utf-8"), public_key)
        ).decode("ascii")
        return encrypted_image, encrypted_caption

    @staticmethod
    def decrypt_post(owner, encrypted_image_bytes: bytes, encrypted_caption: str) -> tuple:
        record = EncryptionService._key_record(owner, KeyRecord.Algorithm.RSA)
        private_key = KeyManagementModule.get_private_key(record)
        image = EncryptionService._rsa_decrypt_chunks(encrypted_image_bytes, private_key)
        caption = EncryptionService._rsa_decrypt_chunks(
            base64.b64decode(encrypted_caption, validate=True), private_key
        ).decode("utf-8")
        return image, caption
