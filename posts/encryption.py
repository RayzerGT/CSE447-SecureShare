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
    and `decrypt_for_display` when rendering a post. Every post is
    friends-only - there is no public tier - so this applies to all posts
    uniformly, with no visibility flag to branch on.
"""

from crypto_core.encryption_service import EncryptionService
from crypto_core.mac.hmac_scratch import compute_mac, verify_mac


def _mac_key(post) -> bytes:
    return f"post:{post.owner_id}".encode("utf-8")


def _mac_payload(image_bytes: bytes, encrypted_caption: str) -> bytes:
    return image_bytes + b"\x00" + encrypted_caption.encode("ascii")


def encrypt_and_store(post, image_bytes: bytes, caption: str) -> None:
    """Populate post.encrypted_image_blob / encrypted_caption / mac_tag."""
    encrypted_image, encrypted_caption = EncryptionService.encrypt_post(post.owner, image_bytes, caption)
    post.encrypted_image_blob = encrypted_image
    post.encrypted_caption = encrypted_caption
    post.mac_tag = compute_mac(_mac_payload(encrypted_image, encrypted_caption), _mac_key(post)).hex()
    post.caption = ""


def decrypt_for_display(post) -> tuple:
    """Return (image_bytes, caption) after verifying the MAC and decrypting."""
    if not post.encrypted_image_blob or not post.encrypted_caption or not post.mac_tag:
        return _legacy_post_data(post)

    if not verify_mac(
        _mac_payload(bytes(post.encrypted_image_blob), post.encrypted_caption),
        _mac_key(post),
        post.mac_tag,
    ):
        raise ValueError("post MAC verification failed")

    return EncryptionService.decrypt_post(
        post.owner,
        bytes(post.encrypted_image_blob),
        post.encrypted_caption,
    )


def _legacy_post_data(post) -> tuple:
    """Read posts created before encrypted fields were introduced."""
    if not post.image:
        raise ValueError("post has no image data")
    with post.image.open("rb") as image_file:
        image_bytes = image_file.read()
    return image_bytes, post.caption
