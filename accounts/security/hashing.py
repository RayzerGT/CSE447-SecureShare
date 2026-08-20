"""
accounts/security/hashing.py

REQUIREMENT (CSE447 Project.pdf): "Passwords must be hashed and salted before
storage." All encryption/hashing must be implemented FROM SCRATCH - no
built-in framework hashing (e.g. Django's PBKDF2/bcrypt/argon2 hashers,
hashlib convenience wrappers used as a black box, etc.).

TODO(Afnan Satter):
    1. Implement a from-scratch cryptographic hash function (or a from-scratch
       construction built on primitives you implement yourself) in this file.
    2. Implement per-user random salt generation.
    3. Implement `hash_password` / `verify_password` below.
    4. Wire a custom `django.contrib.auth.hashers.BasePasswordHasher` subclass
       around these functions and register it in `secureshare/settings.py`
       under `PASSWORD_HASHERS` (see the TODO left there).

Everything below is an INSECURE PLACEHOLDER so registration/login flows can
be exercised end-to-end before the real implementation lands. Do not ship this.
"""

import os


def generate_salt() -> str:
    """TODO(Afnan Satter): replace with a from-scratch salt generation scheme."""
    return os.urandom(16).hex()


def hash_password(plain_password: str, salt: str) -> str:
    """
    TODO(Afnan Satter): replace with a from-scratch hashing algorithm.
    Currently just concatenates salt+password (NOT a hash, NOT secure).
    """
    return f"PLACEHOLDER${salt}${plain_password}"


def verify_password(plain_password: str, salt: str, stored_hash: str) -> bool:
    """TODO(Afnan Satter): replace once hash_password is implemented for real."""
    return hash_password(plain_password, salt) == stored_hash
