"""
crypto_core/key_management/kmm.py
Assigned to: Afnan Satter (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "A Key Management Module must handle key
generation, distribution, storage, and rotation."

This module is the single entry point other apps use to obtain keys - they
should never call rsa_scratch/ecc_scratch directly for key material. Backed
by `crypto_core.models.KeyRecord`.

TODO(Afnan Satter):
    1. `generate_key_for_user`: create an RSA or ECC keypair (algorithm
       choice per the "must use at least two different algorithms across
       different operations" requirement - e.g. RSA for profile data, ECC
       for messages, or split by operation as you see fit - coordinate with
       Razeen since he owns the ECC side) and persist a KeyRecord. Private
       key material must itself be protected at rest (e.g. encrypted with a
       KMM-internal master key) - do not store raw private keys in plaintext
       columns.
    2. `get_active_key_for_user`: fetch the current active KeyRecord.
    3. `rotate_key`: generate a new keypair, mark the old KeyRecord inactive,
       and handle re-encryption of data under the new key (or a versioned
       key scheme so old ciphertext stays readable).
    4. `distribute_public_key`: expose a safe way for other users/apps to
       fetch someone's public key (e.g. via accounts.Profile.public_key_reference).
"""

from crypto_core.models import KeyRecord


class KeyManagementModule:
    @staticmethod
    def generate_key_for_user(user, algorithm: str = KeyRecord.Algorithm.RSA) -> KeyRecord:
        raise NotImplementedError("TODO(Afnan Satter): generate + store a keypair for this user.")

    @staticmethod
    def get_active_key_for_user(user, algorithm: str = None) -> KeyRecord:
        raise NotImplementedError("TODO(Afnan Satter): fetch the user's active key record.")

    @staticmethod
    def rotate_key(user, algorithm: str = None) -> KeyRecord:
        raise NotImplementedError("TODO(Afnan Satter): rotate keys and retire the old KeyRecord.")

    @staticmethod
    def distribute_public_key(user, algorithm: str = None) -> str:
        raise NotImplementedError("TODO(Afnan Satter): return the user's public key material.")
