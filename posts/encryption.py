from crypto_core.encryption_service import EncryptionService
from crypto_core.mac.hmac_scratch import compute_mac, verify_mac

def _mac_key(post) -> bytes:
    context = f"secureshare-post-mac:{post.owner_id}".encode("utf-8")
    return compute_mac(context, EncryptionService._mac_root_secret())

def _mac_payload(image_bytes: bytes, encrypted_caption: str) -> bytes:
    return image_bytes + b"\x00" + encrypted_caption.encode("ascii")

def encrypt_and_store(post, image_bytes: bytes, caption: str) -> None:
    encrypted_image, encrypted_caption = EncryptionService.encrypt_post(post.owner, image_bytes, caption)
    post.encrypted_image_blob = encrypted_image
    post.encrypted_caption = encrypted_caption
    post.mac_tag = compute_mac(_mac_payload(encrypted_image, encrypted_caption), _mac_key(post)).hex()
    post.caption = ""

def decrypt_for_display(post) -> tuple:
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
    if not post.image:
        raise ValueError("post has no image data")
    with post.image.open("rb") as image_file:
        image_bytes = image_file.read()
    return image_bytes, post.caption
