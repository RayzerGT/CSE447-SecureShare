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
        root = getattr(settings, "KMM_MASTER_KEY", "") or settings.SECRET_KEY
        return str(root).encode("utf-8")

    @staticmethod
    def _mac_key(sender, recipient) -> bytes:
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
