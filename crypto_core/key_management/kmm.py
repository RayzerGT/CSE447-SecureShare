"""
crypto_core/key_management/kmm.py
Assigned to: Afnan Satter (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "A Key Management Module must handle key
generation, distribution, storage, and rotation."

This module is the single entry point other apps use to obtain keys - they
should never call rsa_scratch/ecc_scratch directly for key material. Backed
by `crypto_core.models.KeyRecord`.

DESIGN
    - generate_key_for_user: creates a keypair via RSACipher (or ECCCipher,
      once Razeen's side lands), stores the public key as plain JSON on
      KeyRecord.public_key (public keys are meant to be public), and stores
      the private key wrapped under the KMM master RSA keypair
      (master_key.py) - never raw - in KeyRecord.encrypted_private_key. Also
      points accounts.Profile.public_key_reference at the new KeyRecord (the
      field is a short CharField, so it holds a *reference* - the
      KeyRecord's id - not the key material itself, which doesn't fit).
    - get_active_key_for_user: the current is_active=True KeyRecord for a
      user (optionally filtered by algorithm, since a user could hold both
      an RSA and an ECC KeyRecord at once).
    - rotate_key: generates a fresh keypair and marks the old KeyRecord
      inactive (rotated_at=now) rather than deleting it - old KeyRecords
      stay in the table and stay decryptable via get_private_key(), so
      ciphertext produced under a since-rotated key remains readable as
      long as the caller remembers which KeyRecord (by id) encrypted it.
      This project doesn't have a bulk "re-encrypt everything under the new
      key" pass - a caller that wants that can fetch the old private key via
      get_private_key(old_record), decrypt, then re-encrypt under the new
      active key.
    - distribute_public_key: hands back the public key JSON for a user -
      safe to give to anyone, since it's public by definition.
    - get_private_key: NOT one of the four nouns in the requirement, but a
      necessary addition - something has to be able to unwrap a stored
      private key to actually decrypt data with it. Only the crypto layer
      (crypto_core/encryption_service.py) should ever call this; never
      expose it through a view/API.

Wrapping a private key under the master key: an RSA private key (or ECC
scalar) is bigger than a single RSA block can hold under our PKCS#1 v1.5-
style padding (see rsa_scratch.py), so `_wrap_private_key`/
`_unwrap_private_key` split it into fixed-size blocks and RSA-encrypt/
decrypt each one under the master key, storing the concatenated ciphertext
as hex in a TextField.
"""

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
    block_size = (n.bit_length() + 7) // 8 - 11  # max plaintext per RSA block (padding overhead)
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
            from crypto_core.asymmetric.ecc_scratch import ECCCipher  # deferred: not implemented yet

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
        """
        Decrypt and return the raw private key material for `key_record`
        ((d, n) for RSA, the scalar for ECC). Internal use by the crypto
        layer only - never expose this through a view/API.
        """
        private_key_bytes = _unwrap_private_key(key_record.encrypted_private_key)
        parsed = json.loads(private_key_bytes)
        if key_record.algorithm == KeyRecord.Algorithm.RSA:
            return (parsed["d"], parsed["n"])
        if key_record.algorithm == KeyRecord.Algorithm.ECC:
            return parsed["scalar"]
        raise ValueError(f"unknown algorithm: {key_record.algorithm}")
