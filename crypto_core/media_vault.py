from django.core.cache import cache

from crypto_core.encryption_service import EncryptionService
from crypto_core.mac.hmac_scratch import compute_mac, verify_mac

_CACHE_SECONDS = 3600


def _mac_key(context: str) -> bytes:
    return compute_mac(context.encode("utf-8"), EncryptionService._mac_root_secret())


def seal(owner, context: str, image_bytes: bytes) -> tuple:
    blob = EncryptionService.encrypt_binary(owner, image_bytes)
    tag = compute_mac(blob, _mac_key(context)).hex()
    return blob, tag


def open_sealed(owner, context: str, blob, tag: str) -> bytes:
    blob = bytes(blob)
    cache_key = f"media-plain:{context}:{tag[:16]}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    if not verify_mac(blob, _mac_key(context), tag):
        raise ValueError("media MAC verification failed")

    plaintext = EncryptionService.decrypt_binary(owner, blob)
    cache.set(cache_key, plaintext, _CACHE_SECONDS)
    return plaintext


def forget(context: str, tag: str) -> None:
    if tag:
        cache.delete(f"media-plain:{context}:{tag[:16]}")
