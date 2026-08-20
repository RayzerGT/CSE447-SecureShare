"""
crypto_core/asymmetric/rsa_scratch.py
Assigned to: Afnan Satter (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "The system must exclusively use asymmetric
encryption algorithms... must implement at least two different asymmetric
encryption algorithms... All encryption algorithms must be implemented from
scratch. Using built-in encryption functions or methods provided by
frameworks... is not allowed."

This module is one of the two required asymmetric algorithms (RSA - the
other, ECC, is Razeen Hassan's, in ecc_scratch.py). Must NOT use
`cryptography`, `pycryptodome`, `rsa`, `hashlib`-based shortcuts for the core
math, etc. Implement key generation (prime generation, modular inverse,
etc.), encryption, and decryption using plain Python arithmetic.

TODO(Afnan Satter):
    1. Implement prime generation (e.g. Miller-Rabin) and keypair generation.
    2. Implement `encrypt` / `decrypt` using modular exponentiation.
    3. Decide a padding scheme (document your choice) to avoid textbook-RSA
       pitfalls.
    4. Register this cipher with `crypto_core/encryption_service.py` (Munia's
       facade) and with your own Key Management Module (kmm.py).

Everything below raises NotImplementedError - callers should not silently
get insecure output from this particular module (contrast with the
INSECURE PLACEHOLDER pattern used in accounts/security/*, which is fine for
password hashing during early dev but not acceptable for the actual graded
crypto deliverable).
"""

from dataclasses import dataclass


@dataclass
class RSAKeyPair:
    public_key: tuple  # (e, n)
    private_key: tuple  # (d, n)


class RSACipher:
    """From-scratch RSA. See module docstring for what's left to implement."""

    @staticmethod
    def generate_keypair(key_size_bits: int = 2048) -> RSAKeyPair:
        raise NotImplementedError("TODO(Afnan Satter): implement RSA keypair generation from scratch.")

    @staticmethod
    def encrypt(plaintext: bytes, public_key: tuple) -> bytes:
        raise NotImplementedError("TODO(Afnan Satter): implement RSA encryption from scratch.")

    @staticmethod
    def decrypt(ciphertext: bytes, private_key: tuple) -> bytes:
        raise NotImplementedError("TODO(Afnan Satter): implement RSA decryption from scratch.")
