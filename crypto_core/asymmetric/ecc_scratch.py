"""
crypto_core/asymmetric/ecc_scratch.py
Assigned to: Razeen Hassan (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): second required asymmetric algorithm,
distinct from RSA (see rsa_scratch.py, Afnan Satter's). Must be implemented
from scratch - no `cryptography`/`ecdsa`/`pycryptodome` etc. for the core
elliptic-curve arithmetic.

TODO(Razeen Hassan):
    1. Pick a curve (e.g. a small named curve or a textbook curve over F_p)
       and implement point addition/doubling and scalar multiplication.
    2. Implement keypair generation (private scalar + public point).
    3. Implement an encryption scheme on top of it (e.g. ECIES-style hybrid
       construction, or ECC-based key agreement feeding into your own
       asymmetric-only scheme per the "exclusively asymmetric" requirement -
       document whatever design choice you make here).
    4. Register this cipher with `crypto_core/encryption_service.py` (Munia's
       facade).
"""

from dataclasses import dataclass


@dataclass
class ECCKeyPair:
    public_key: tuple  # curve point (x, y)
    private_key: int   # scalar


class ECCCipher:
    """From-scratch ECC. See module docstring for what's left to implement."""

    @staticmethod
    def generate_keypair() -> ECCKeyPair:
        raise NotImplementedError("TODO(Razeen Hassan): implement ECC keypair generation from scratch.")

    @staticmethod
    def encrypt(plaintext: bytes, public_key: tuple) -> bytes:
        raise NotImplementedError("TODO(Razeen Hassan): implement ECC encryption from scratch.")

    @staticmethod
    def decrypt(ciphertext: bytes, private_key: int) -> bytes:
        raise NotImplementedError("TODO(Razeen Hassan): implement ECC decryption from scratch.")
