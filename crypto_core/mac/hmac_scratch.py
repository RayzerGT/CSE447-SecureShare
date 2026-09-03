"""
crypto_core/mac/hmac_scratch.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "Message Authentication Codes (MAC) such as
CBC-MAC or HMAC must verify data integrity and detect unauthorized
modifications."

DESIGN CHOICE (documented per the assignment's "document your choice" rule):
    - Underlying primitive: a from-scratch SHA-256 implementation
      (_sha256_scratch below). No `hashlib`, `hmac`, or any other library is
      used anywhere in this file - the compression function, message
      schedule, and padding are all implemented by hand from the FIPS 180-4
      specification, using only plain integer/bitwise arithmetic.
    - Construction: standard HMAC (RFC 2104), built on top of that from-
      scratch hash:
          HMAC(K, m) = H( (K' xor opad) || H( (K' xor ipad) || m ) )
      where K' is the key padded/hashed to the hash's block size (64 bytes
      for SHA-256).
    - `verify_mac` compares tags in constant time (no early-exit on the
      first differing byte) so timing side-channels can't be used to guess
      the tag byte-by-byte.

Used by crypto_core/encryption_service.py to tag encrypted posts, DMs, and
profile data, and to check that tag before decrypting on read.
"""

# ---------------------------------------------------------------------------
# From-scratch SHA-256 (FIPS 180-4). No hashlib/hmac used anywhere here.
# ---------------------------------------------------------------------------

_MASK32 = 0xFFFFFFFF

# First 32 bits of the fractional parts of the cube roots of the first 64
# primes (the standard SHA-256 round constants).
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# First 32 bits of the fractional parts of the square roots of the first 8
# primes (the standard SHA-256 initial hash values).
_H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _sha256_scratch(message: bytes) -> bytes:
    """From-scratch SHA-256. Returns the 32-byte digest."""
    # --- padding ---
    msg_len_bits = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0x00)
    padded += msg_len_bits.to_bytes(8, "big")

    h = list(_H_INIT)

    # --- process each 512-bit (64-byte) chunk ---
    for chunk_start in range(0, len(padded), 64):
        chunk = padded[chunk_start:chunk_start + 64]

        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4:i * 4 + 4], "big")
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32

        a, b, c, d, e, f, g, hh = h

        for i in range(64):
            s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + s1 + ch + _K[i] + w[i]) & _MASK32
            s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & _MASK32

            hh = g
            g = f
            f = e
            e = (d + temp1) & _MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & _MASK32

        h = [
            (h[0] + a) & _MASK32, (h[1] + b) & _MASK32, (h[2] + c) & _MASK32, (h[3] + d) & _MASK32,
            (h[4] + e) & _MASK32, (h[5] + f) & _MASK32, (h[6] + g) & _MASK32, (h[7] + hh) & _MASK32,
        ]

    return b"".join(word.to_bytes(4, "big") for word in h)


# ---------------------------------------------------------------------------
# HMAC construction (RFC 2104) on top of the from-scratch hash above.
# ---------------------------------------------------------------------------

_BLOCK_SIZE = 64  # SHA-256 block size in bytes
_DIGEST_SIZE = 32


def _normalize_key(key: bytes) -> bytes:
    if len(key) > _BLOCK_SIZE:
        key = _sha256_scratch(key)
    return key + b"\x00" * (_BLOCK_SIZE - len(key))


def compute_mac(data: bytes, key: bytes) -> bytes:
    """
    Compute an HMAC-SHA256-style tag over `data` under `key`, using the
    from-scratch primitives above. Returns the 32-byte tag.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if isinstance(key, str):
        key = key.encode("utf-8")

    k_prime = _normalize_key(key)
    o_key_pad = bytes(b ^ 0x5C for b in k_prime)
    i_key_pad = bytes(b ^ 0x36 for b in k_prime)

    inner = _sha256_scratch(i_key_pad + data)
    return _sha256_scratch(o_key_pad + inner)


def verify_mac(data: bytes, key: bytes, mac_tag: bytes) -> bool:
    """
    Recompute the tag and compare it to `mac_tag` in constant time (to avoid
    leaking how many leading bytes matched via a timing side-channel).
    """
    if isinstance(mac_tag, str):
        mac_tag = bytes.fromhex(mac_tag) if _looks_like_hex(mac_tag) else mac_tag.encode("utf-8")

    expected = compute_mac(data, key)

    if len(expected) != len(mac_tag):
        return False

    diff = 0
    for x, y in zip(expected, mac_tag):
        diff |= x ^ y
    return diff == 0


def _looks_like_hex(s: str) -> bool:
    if len(s) != _DIGEST_SIZE * 2:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False