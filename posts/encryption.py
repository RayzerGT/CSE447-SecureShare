"""
posts/encryption.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "Users must be able to create, view, and
edit posts... with all data automatically encrypted before storage and
decrypted on retrieval" / "All critical data (user information, posts,
keys, etc.) must be stored in encrypted form."

TODO(Mos. Mahabuba Akter Munia):
    Implement using crypto_core.encryption_service.EncryptionService
    (encrypt_post / decrypt_post) + crypto_core.mac (compute_mac/verify_mac).
    Call `encrypt_and_store` from posts/views.py (Afnan's) on upload/edit,
    and `decrypt_for_display` when rendering a post whose visibility isn't
    PUBLIC (or per your team's final threat model - document the choice).
"""

from crypto_core.encryption_service import EncryptionService


def encrypt_and_store(post, image_bytes: bytes, caption: str) -> None:
    """Populate post.encrypted_image_blob / encrypted_caption / mac_tag."""
    raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): encrypt + MAC post data before saving.")


def decrypt_for_display(post) -> tuple:
    """Return (image_bytes, caption) after verifying the MAC and decrypting."""
    raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): verify MAC + decrypt post data for display.")
