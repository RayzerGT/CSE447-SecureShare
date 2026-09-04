import base64
import json

from django.conf import settings

from crypto_core.asymmetric.ecc_scratch import ECCCipher
from crypto_core.asymmetric.rsa_scratch import RSACipher
from crypto_core.key_management.kmm import KeyManagementModule
from crypto_core.mac.hmac_scratch import compute_mac, verify_mac
from crypto_core.models import KeyRecord

_TEXT_ENVELOPE_VERSION = "v1"
_BINARY_ENVELOPE_MAGIC = b"SSE1"
_BINARY_KEY_ID_BYTES = 4


class EncryptionService:
    @staticmethod
    def _key_record(user, algorithm: str) -> KeyRecord:
        try:
            return KeyManagementModule.get_active_key_for_user(user, algorithm)
        except KeyRecord.DoesNotExist:
            return KeyManagementModule.generate_key_for_user(user, algorithm)

    @staticmethod
    def _record_for_decrypt(user, algorithm: str, key_id) -> KeyRecord:
        if key_id is not None:
            record = KeyRecord.objects.filter(pk=key_id, owner=user, algorithm=algorithm).first()
            if record is not None:
                return record
            raise ValueError(
                f"ciphertext was produced under {algorithm} key {key_id}, which no longer exists"
            )
        return EncryptionService._key_record(user, algorithm)

    @staticmethod
    def _wrap_text(key_id: int, ciphertext: bytes) -> str:
        return f"{_TEXT_ENVELOPE_VERSION}.{key_id}.{base64.b64encode(ciphertext).decode('ascii')}"

    @staticmethod
    def _unwrap_text(value: str) -> tuple:
        parts = value.split(".", 2)
        if len(parts) == 3 and parts[0] == _TEXT_ENVELOPE_VERSION and parts[1].isdigit():
            return int(parts[1]), base64.b64decode(parts[2], validate=True)
        return None, base64.b64decode(value, validate=True)

    @staticmethod
    def _wrap_binary(key_id: int, ciphertext: bytes) -> bytes:
        return _BINARY_ENVELOPE_MAGIC + key_id.to_bytes(_BINARY_KEY_ID_BYTES, "big") + ciphertext

    @staticmethod
    def _unwrap_binary(blob: bytes) -> tuple:
        blob = bytes(blob)
        header = len(_BINARY_ENVELOPE_MAGIC) + _BINARY_KEY_ID_BYTES
        if blob[:len(_BINARY_ENVELOPE_MAGIC)] == _BINARY_ENVELOPE_MAGIC:
            key_id = int.from_bytes(blob[len(_BINARY_ENVELOPE_MAGIC):header], "big")
            return key_id, blob[header:]
        return None, blob

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
        return EncryptionService._wrap_text(record.pk, ciphertext)

    @staticmethod
    def decrypt_profile_data(user, ciphertext: str) -> str:
        key_id, raw = EncryptionService._unwrap_text(ciphertext)
        record = EncryptionService._record_for_decrypt(user, KeyRecord.Algorithm.RSA, key_id)
        plaintext = EncryptionService._rsa_decrypt_chunks(
            raw, KeyManagementModule.get_private_key(record)
        )
        return plaintext.decode("utf-8")

    @staticmethod
    def encrypt_message(sender, recipient, plaintext: str) -> tuple:
        record = EncryptionService._key_record(recipient, KeyRecord.Algorithm.ECC)
        ciphertext = ECCCipher.encrypt(plaintext.encode("utf-8"), EncryptionService._public_key(record))
        mac_tag = compute_mac(ciphertext, EncryptionService._mac_key(sender, recipient)).hex()
        return EncryptionService._wrap_text(record.pk, ciphertext), mac_tag

    @staticmethod
    def decrypt_message(sender, recipient, ciphertext: str, mac_tag: str) -> str:
        key_id, raw_ciphertext = EncryptionService._unwrap_text(ciphertext)
        if not verify_mac(raw_ciphertext, EncryptionService._mac_key(sender, recipient), mac_tag):
            raise ValueError("message MAC verification failed")
        record = EncryptionService._record_for_decrypt(recipient, KeyRecord.Algorithm.ECC, key_id)
        plaintext = ECCCipher.decrypt(raw_ciphertext, KeyManagementModule.get_private_key(record))
        return plaintext.decode("utf-8")

    @staticmethod
    def encrypt_post(owner, image_bytes: bytes, caption: str) -> tuple:
        record = EncryptionService._key_record(owner, KeyRecord.Algorithm.RSA)
        public_key = EncryptionService._public_key(record)
        encrypted_image = EncryptionService._wrap_binary(
            record.pk, EncryptionService._rsa_encrypt_chunks(image_bytes, public_key)
        )
        encrypted_caption = EncryptionService._wrap_text(
            record.pk, EncryptionService._rsa_encrypt_chunks(caption.encode("utf-8"), public_key)
        )
        return encrypted_image, encrypted_caption

    @staticmethod
    def decrypt_post(owner, encrypted_image_bytes: bytes, encrypted_caption: str) -> tuple:
        image_key_id, raw_image = EncryptionService._unwrap_binary(encrypted_image_bytes)
        caption_key_id, raw_caption = EncryptionService._unwrap_text(encrypted_caption)

        image_record = EncryptionService._record_for_decrypt(
            owner, KeyRecord.Algorithm.RSA, image_key_id
        )
        caption_record = EncryptionService._record_for_decrypt(
            owner, KeyRecord.Algorithm.RSA, caption_key_id
        )

        image = EncryptionService._rsa_decrypt_chunks(
            raw_image, KeyManagementModule.get_private_key(image_record)
        )
        caption = EncryptionService._rsa_decrypt_chunks(
            raw_caption, KeyManagementModule.get_private_key(caption_record)
        ).decode("utf-8")
        return image, caption
