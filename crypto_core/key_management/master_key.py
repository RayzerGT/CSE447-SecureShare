"""
crypto_core/key_management/master_key.py
Assigned to: Afnan Satter (backs kmm.py)

The Key Management Module must store each user's private key encrypted at
rest, never raw (see kmm.py + the TODO on crypto_core.models.KeyRecord).
Per the project's "exclusively asymmetric encryption" requirement, that
wrapping has to be done with RSA (crypto_core.asymmetric.rsa_scratch), not a
symmetric cipher - which means it needs its own RSA keypair to wrap/unwrap
*other* keys with. That's what this module holds: one process-wide "master"
RSA keypair, playing the same root-secret role for encrypted key material
that SECRET_KEY plays for Django's own cryptographic signing.

Every root-of-trust has to bottom out somewhere outside the data it
protects - a real KMS roots this in an HSM; here it's an env var, exactly
like SECRET_KEY already is in this project.

CONFIGURATION (mirrors SECRET_KEY's pattern in settings.py):
    - Set KMM_MASTER_KEY in .env as "e:d:n" (three colon-separated integers)
      to pin a stable master key. This is required for previously-wrapped
      private keys to stay decryptable across a process restart - matters
      as soon as there's real encrypted key material you want to keep (e.g.
      on the shared Aiven DB demo). Generate one with:
          python -c "from crypto_core.key_management.master_key import generate_master_key_env_line; print(generate_master_key_env_line())"
      and paste the printed line into your .env.
    - If KMM_MASTER_KEY is unset, a fresh master keypair is generated in
      memory the first time it's needed and cached for the life of the
      process - fine for throwaway local experimentation, but anything
      wrapped under it becomes permanently unreadable the next time the
      process restarts (the dev-only equivalent of settings.py's
      "insecure-dev-key-change-me" fallback for SECRET_KEY).
"""

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
    """Generate a fresh master keypair, formatted as a ready-to-paste .env line."""
    keypair = RSACipher.generate_keypair(_MASTER_KEY_BITS)
    return f"KMM_MASTER_KEY={_format_master_key(keypair)}"


def get_master_keypair() -> RSAKeyPair:
    """The process-wide master RSA keypair used to wrap/unwrap other users'
    private keys at rest. Cached after the first call."""
    global _cached_keypair
    if _cached_keypair is not None:
        return _cached_keypair

    raw = getattr(settings, "KMM_MASTER_KEY", "") or ""
    _cached_keypair = _parse_master_key(raw) if raw else RSACipher.generate_keypair(_MASTER_KEY_BITS)
    return _cached_keypair
