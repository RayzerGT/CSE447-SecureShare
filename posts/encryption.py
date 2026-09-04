from django.core.cache import cache

from crypto_core.encryption_service import EncryptionService
from crypto_core.mac.hmac_scratch import compute_mac, verify_mac

_PLAINTEXT_CACHE_SECONDS = 3600


def _mac_key(post) -> bytes:
    context = f"secureshare-post-mac:{post.owner_id}".encode("utf-8")
    return compute_mac(context, EncryptionService._mac_root_secret())


def _mac_payload(image_bytes: bytes, encrypted_caption: str, thumbnail_bytes: bytes = b"") -> bytes:
    payload = image_bytes + b"\x00" + encrypted_caption.encode("ascii")
    if thumbnail_bytes:
        payload += b"\x00" + thumbnail_bytes
    return payload


def _caption_mac_payload(post, encrypted_caption: str) -> bytes:
    return f"secureshare-post-caption:{post.pk}:".encode("utf-8") + encrypted_caption.encode("ascii")


def _cache_key(post, variant: str) -> str:
    return f"post-plain:{post.pk}:{variant}:{post.mac_tag[:16]}"


def encrypt_and_store(post, image_bytes: bytes, caption: str, thumbnail_bytes: bytes = b"") -> None:
    if post.pk and post.mac_tag:
        for variant in ("image", "thumbnail", "caption"):
            cache.delete(_cache_key(post, variant))

    encrypted_image, encrypted_caption = EncryptionService.encrypt_post(post.owner, image_bytes, caption)
    encrypted_thumbnail = (
        EncryptionService.encrypt_binary(post.owner, thumbnail_bytes) if thumbnail_bytes else b""
    )

    post.encrypted_image_blob = encrypted_image
    post.encrypted_thumbnail_blob = encrypted_thumbnail
    post.encrypted_caption = encrypted_caption
    post.mac_tag = compute_mac(
        _mac_payload(encrypted_image, encrypted_caption, encrypted_thumbnail), _mac_key(post)
    ).hex()
    post.caption = ""

    if post.pk:
        seal_caption(post)


def seal_caption(post) -> None:
    post.caption_mac_tag = compute_mac(
        _caption_mac_payload(post, post.encrypted_caption), _mac_key(post)
    ).hex()


ENCRYPTED_BLOB_FIELDS = ("encrypted_image_blob", "encrypted_thumbnail_blob")


def decrypt_caption(post) -> str:
    if not post.encrypted_caption:
        return post.caption

    if post.caption_mac_tag:
        if not verify_mac(
            _caption_mac_payload(post, post.encrypted_caption), _mac_key(post), post.caption_mac_tag
        ):
            raise ValueError("post caption MAC verification failed")
    else:
        _verify_full_mac(post)

    cache_key = _cache_key(post, "caption")
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    caption = EncryptionService.decrypt_text(post.owner, post.encrypted_caption)
    cache.set(cache_key, caption, _PLAINTEXT_CACHE_SECONDS)
    return caption


def _verify_full_mac(post) -> None:
    if not verify_mac(
        _mac_payload(
            bytes(post.encrypted_image_blob or b""),
            post.encrypted_caption,
            bytes(post.encrypted_thumbnail_blob or b""),
        ),
        _mac_key(post),
        post.mac_tag,
    ):
        raise ValueError("post MAC verification failed")


def decrypt_image(post, prefer_thumbnail: bool = False) -> bytes:
    blob = post.encrypted_thumbnail_blob if prefer_thumbnail else post.encrypted_image_blob
    variant = "thumbnail" if prefer_thumbnail else "image"

    if not blob:
        if prefer_thumbnail:
            return decrypt_image(post, prefer_thumbnail=False)
        return _legacy_image(post)

    cache_key = _cache_key(post, variant)
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    _verify_full_mac(post)
    plaintext = EncryptionService.decrypt_binary(post.owner, bytes(blob))
    cache.set(cache_key, plaintext, _PLAINTEXT_CACHE_SECONDS)
    return plaintext


def decrypt_for_display(post) -> tuple:
    if not post.encrypted_image_blob or not post.encrypted_caption or not post.mac_tag:
        return _legacy_post_data(post)
    _verify_full_mac(post)
    return decrypt_image(post), decrypt_caption(post)


def _legacy_image(post) -> bytes:
    if not post.image:
        raise ValueError("post has no image data")
    with post.image.open("rb") as image_file:
        return image_file.read()


def _legacy_post_data(post) -> tuple:
    return _legacy_image(post), post.caption
