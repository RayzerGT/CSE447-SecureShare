import json

from django.utils import timezone

from crypto_core.asymmetric.rsa_scratch import RSACipher
from crypto_core.key_management.master_key import get_master_keypair
from crypto_core.models import KeyRecord

def _serialize_public_key(algorithm: str, public_key) -> str:
    if algorithm == KeyRecord.Algorithm.RSA:
        e, n = public_key
        return json.dumps({"e": e, "n": n})
    if algorithm == KeyRecord.Algorithm.ECC:
        x, y = public_key
        return json.dumps({"x": x, "y": y})
    raise ValueError(f"unknown algorithm: {algorithm}")

def _wrap_private_key(private_key_bytes: bytes) -> str:
    master_public_key = get_master_keypair().public_key
    _, n = master_public_key
    block_size = (n.bit_length() + 7) // 8 - 11
    chunks = [private_key_bytes[i:i + block_size] for i in range(0, len(private_key_bytes), block_size)]
    ciphertext = b"".join(RSACipher.encrypt(chunk, master_public_key) for chunk in (chunks or [b""]))
    return ciphertext.hex()

def _unwrap_private_key(wrapped_hex: str) -> bytes:
    master_private_key = get_master_keypair().private_key
    _, n = master_private_key
    block_bytes = (n.bit_length() + 7) // 8
    ciphertext = bytes.fromhex(wrapped_hex)
    return b"".join(
        RSACipher.decrypt(ciphertext[i:i + block_bytes], master_private_key)
        for i in range(0, len(ciphertext), block_bytes)
    )

class KeyManagementModule:
    @staticmethod
    def generate_key_for_user(user, algorithm: str = KeyRecord.Algorithm.RSA) -> KeyRecord:
        if algorithm == KeyRecord.Algorithm.RSA:
            keypair = RSACipher.generate_keypair()
            private_key_bytes = json.dumps({"d": keypair.private_key[0], "n": keypair.private_key[1]}).encode()
        elif algorithm == KeyRecord.Algorithm.ECC:
            from crypto_core.asymmetric.ecc_scratch import ECCCipher

            keypair = ECCCipher.generate_keypair()
            private_key_bytes = json.dumps({"scalar": keypair.private_key}).encode()
        else:
            raise ValueError(f"unknown algorithm: {algorithm}")

        KeyRecord.objects.filter(owner=user, algorithm=algorithm, is_active=True).update(
            is_active=False, rotated_at=timezone.now()
        )

        key_record = KeyRecord.objects.create(
            owner=user,
            algorithm=algorithm,
            public_key=_serialize_public_key(algorithm, keypair.public_key),
            encrypted_private_key=_wrap_private_key(private_key_bytes),
            is_active=True,
        )

        profile = getattr(user, "profile", None)
        if profile is not None:
            profile.public_key_reference = str(key_record.pk)
            profile.save(update_fields=["public_key_reference"])

        return key_record

    @staticmethod
    def get_active_key_for_user(user, algorithm: str = None) -> KeyRecord:
        queryset = KeyRecord.objects.filter(owner=user, is_active=True)
        if algorithm:
            queryset = queryset.filter(algorithm=algorithm)
        key_record = queryset.first()
        if key_record is None:
            raise KeyRecord.DoesNotExist(f"no active {algorithm or ''} key for {user}".strip())
        return key_record

    @staticmethod
    def rotate_key(user, algorithm: str = None) -> KeyRecord:
        return KeyManagementModule.generate_key_for_user(user, algorithm or KeyRecord.Algorithm.RSA)

    @staticmethod
    def distribute_public_key(user, algorithm: str = None) -> str:
        return KeyManagementModule.get_active_key_for_user(user, algorithm).public_key

    @staticmethod
    def get_private_key(key_record: KeyRecord):
        private_key_bytes = _unwrap_private_key(key_record.encrypted_private_key)
        parsed = json.loads(private_key_bytes)
        if key_record.algorithm == KeyRecord.Algorithm.RSA:
            return (parsed["d"], parsed["n"])
        if key_record.algorithm == KeyRecord.Algorithm.ECC:
            return parsed["scalar"]
        raise ValueError(f"unknown algorithm: {key_record.algorithm}")
