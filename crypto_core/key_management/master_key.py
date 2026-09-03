from django.conf import settings

from crypto_core.asymmetric.rsa_scratch import RSACipher, RSAKeyPair

_MASTER_KEY_BITS = 2048

_cached_keypair = None

def _parse_master_key(raw: str) -> RSAKeyPair:
    e_str, d_str, n_str = raw.split(":")
    e, d, n = int(e_str), int(d_str), int(n_str)
    return RSAKeyPair(public_key=(e, n), private_key=(d, n))

def _format_master_key(keypair: RSAKeyPair) -> str:
    e, n = keypair.public_key
    d, _ = keypair.private_key
    return f"{e}:{d}:{n}"

def generate_master_key_env_line() -> str:
    keypair = RSACipher.generate_keypair(_MASTER_KEY_BITS)
    return f"KMM_MASTER_KEY={_format_master_key(keypair)}"

def get_master_keypair() -> RSAKeyPair:
    global _cached_keypair
    if _cached_keypair is not None:
        return _cached_keypair

    raw = getattr(settings, "KMM_MASTER_KEY", "") or ""
    _cached_keypair = _parse_master_key(raw) if raw else RSACipher.generate_keypair(_MASTER_KEY_BITS)
    return _cached_keypair
