"""
crypto_core/asymmetric/ecc_scratch.py
Assigned to: Razeen Hassan (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): second required asymmetric algorithm,
distinct from RSA (see rsa_scratch.py, Afnan Satter's). "All encryption
algorithms must be implemented from scratch." Nothing here imports
`cryptography`, `ecdsa`, `pycryptodome`, or any other crypto library - the
curve arithmetic, the modular square root, the point encoding and the
encryption scheme are all written out below. Only Python's built-in integer
arithmetic (`pow`, `%`, `*`) and `os.urandom` for randomness are used, the
same line Afnan drew in rsa_scratch.py.

DESIGN
------
Curve: secp256k1, a standard named curve over F_p:

        y^2 = x^3 + 7   (mod p),  p = 2^256 - 2^32 - 977

    Using published parameters rather than inventing a curve is deliberate -
    hand-rolled curve parameters are very easy to get catastrophically wrong
    (singular curves, tiny subgroups, small embedding degree). The *code* is
    from scratch; the constants are the well-known ones and can be checked
    against the SEC 2 standard.

    p = 3 (mod 4), which makes modular square roots a single exponentiation
    (see _mod_sqrt) instead of needing full Tonelli-Shanks.

Encryption: EC-ElGamal, NOT ECIES.
    The obvious ECC encryption scheme is ECIES, but ECIES is a *hybrid*: it
    does an ECDH key agreement and then encrypts the payload with a
    symmetric cipher (AES). The project explicitly forbids that - "The
    system must exclusively use asymmetric encryption algorithms...
    symmetric encryption is not allowed." EC-ElGamal keeps everything in the
    asymmetric world:

        keygen     private d random in [1, n-1];  public Q = d*G
        encrypt    pick random k in [1, n-1]
                   C1 = k*G
                   C2 = M + k*Q      (M = plaintext encoded as a curve point)
        decrypt    M = C2 - d*C1     (since C2 - d*C1 = M + k*(d*G) - d*(k*G))

    A fresh random k is drawn for every block, so encrypting the same
    plaintext twice produces completely different ciphertext.

Encoding plaintext as a curve point: Koblitz's method (_encode_point).
    A message chunk m is embedded in the x-coordinate as x = m*K + j, trying
    j = 0, 1, 2, ... until x^3 + 7 is a quadratic residue mod p (i.e. until
    the x actually lands on the curve). Roughly half of all x values work,
    so this succeeds almost immediately; K = 1024 gives 1024 attempts before
    giving up, which will not happen in practice. Decoding is just
    m = x // K.

Chunking and framing: a single point carries _CHUNK_SIZE = 30 bytes, so
    longer plaintexts are split. The whole plaintext gets a 4-byte
    big-endian length header first, then is zero-padded up to a chunk
    boundary; decrypt concatenates the chunks and truncates back to the
    stated length. Without the header the padding would be
    indistinguishable from trailing zero bytes in the real message.

Wire format: each block is two compressed points, 33 bytes each:

        [0x02|0x03][32-byte x]   for C1, then the same for C2

    The prefix byte records the parity of y, which is enough to recover y on
    decompression via the same _mod_sqrt used for encoding. That halves the
    ciphertext versus storing both coordinates, and it reuses machinery this
    module needs anyway.

KNOWN LIMITATIONS (documented rather than silently ignored)
    - EC-ElGamal is malleable: an attacker who cannot read a ciphertext can
      still transform it into a related one. Integrity/authenticity is not
      this module's job - it comes from the MAC layer
      (crypto_core/mac/hmac_scratch.py, Munia's) applied over the
      ciphertext. Do not use this without that MAC.
    - Ciphertext length reveals plaintext length (rounded up to 30 bytes).
    - Encrypting each block independently means identical 30-byte blocks
      within one message are *not* linkable (fresh k each), but block count
      is still visible.
    - Pure-Python scalar multiplication is not constant-time and leaks
      timing information about the private scalar. Acceptable for a course
      project; called out so nobody mistakes this for production code.
"""

import os
from dataclasses import dataclass

# --- secp256k1 domain parameters (SEC 2) -----------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_G = (_GX, _GY)

_COORD_BYTES = 32          # 256-bit field -> 32-byte coordinates
_POINT_BYTES = 33          # compressed point: parity prefix + x
_KOBLITZ_K = 1024          # attempts available when embedding a chunk
_CHUNK_SIZE = 30           # plaintext bytes per curve point
_LENGTH_HEADER = 4         # bytes used for the big-endian plaintext length

# The point at infinity (identity element) is represented as None throughout.
_INFINITY = None


@dataclass
class ECCKeyPair:
    public_key: tuple  # curve point (x, y)
    private_key: int   # scalar


# --- field / curve arithmetic ----------------------------------------------


def _mod_inverse(a: int, m: int = _P) -> int:
    """Modular inverse via the extended Euclidean algorithm."""
    old_r, r = a % m, m
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
    if old_r != 1:
        raise ValueError("modular inverse does not exist")
    return old_s % m


def _mod_sqrt(a: int) -> int:
    """
    Square root mod p. secp256k1's p is 3 (mod 4), so a^((p+1)/4) is a root
    whenever one exists. Raises ValueError if `a` is not a quadratic residue.
    """
    a %= _P
    if a == 0:
        return 0
    root = pow(a, (_P + 1) // 4, _P)
    if (root * root) % _P != a:
        raise ValueError("value is not a quadratic residue mod p")
    return root


def _curve_rhs(x: int) -> int:
    """The right-hand side of the curve equation: x^3 + a*x + b (mod p)."""
    return (pow(x, 3, _P) + _A * x + _B) % _P


def is_on_curve(point) -> bool:
    if point is _INFINITY:
        return True
    x, y = point
    if not (0 <= x < _P and 0 <= y < _P):
        return False
    return (y * y) % _P == _curve_rhs(x)


def _point_negate(point):
    if point is _INFINITY:
        return _INFINITY
    x, y = point
    return (x, (-y) % _P)


def _point_add(p1, p2):
    """Elliptic-curve point addition (chord-and-tangent), including doubling."""
    if p1 is _INFINITY:
        return p2
    if p2 is _INFINITY:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % _P == 0:
        # P + (-P) = point at infinity
        return _INFINITY

    if p1 == p2:
        # Tangent slope: (3x^2 + a) / 2y
        slope = (3 * x1 * x1 + _A) * _mod_inverse(2 * y1) % _P
    else:
        # Chord slope: (y2 - y1) / (x2 - x1)
        slope = (y2 - y1) * _mod_inverse(x2 - x1) % _P

    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return (x3, y3)


def _scalar_mult(k: int, point):
    """Double-and-add scalar multiplication."""
    if point is _INFINITY or k % _N == 0:
        return _INFINITY
    if k < 0:
        return _scalar_mult(-k, _point_negate(point))

    result = _INFINITY
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _random_scalar() -> int:
    """A uniformly random scalar in [1, n-1]."""
    while True:
        candidate = int.from_bytes(os.urandom(_COORD_BYTES), "big")
        if 1 <= candidate < _N:
            return candidate


# --- point <-> bytes (compressed form) -------------------------------------


def _compress_point(point) -> bytes:
    if point is _INFINITY:
        raise ValueError("cannot serialize the point at infinity")
    x, y = point
    prefix = b"\x03" if y & 1 else b"\x02"
    return prefix + x.to_bytes(_COORD_BYTES, "big")


def _decompress_point(data: bytes):
    if len(data) != _POINT_BYTES or data[0] not in (0x02, 0x03):
        raise ValueError("malformed compressed point")
    x = int.from_bytes(data[1:], "big")
    y = _mod_sqrt(_curve_rhs(x))
    # _mod_sqrt returns one of the two roots; pick the one with the recorded parity.
    if (y & 1) != (data[0] & 1):
        y = (-y) % _P
    point = (x, y)
    if not is_on_curve(point):
        raise ValueError("decompressed point is not on the curve")
    return point


# --- plaintext <-> curve point (Koblitz embedding) -------------------------


def _encode_point(chunk: bytes):
    """
    Embed up to _CHUNK_SIZE bytes into a curve point by searching for a
    valid x of the form m*K + j. See the module docstring.
    """
    if len(chunk) > _CHUNK_SIZE:
        raise ValueError(f"chunk too large to encode ({len(chunk)} > {_CHUNK_SIZE} bytes)")
    m = int.from_bytes(chunk, "big")
    base = m * _KOBLITZ_K
    for j in range(_KOBLITZ_K):
        x = base + j
        if x >= _P:
            break
        try:
            y = _mod_sqrt(_curve_rhs(x))
        except ValueError:
            continue  # x^3 + 7 wasn't a square; try the next candidate
        return (x, y)
    raise ValueError("failed to embed chunk on the curve (should be practically impossible)")


def _decode_point(point) -> bytes:
    x, _ = point
    m = x // _KOBLITZ_K
    try:
        return m.to_bytes(_CHUNK_SIZE, "big")
    except OverflowError:
        # Happens when the recovered point isn't one we encoded - overwhelmingly
        # the "decrypting with the wrong private key" case. Surface it as a
        # ValueError so callers have one exception type to handle, rather than
        # leaking an int-conversion error from the internals.
        raise ValueError("decryption failed (recovered point does not decode - wrong key?)") from None


# --- public API -------------------------------------------------------------


class ECCCipher:
    """
    From-scratch ECC (secp256k1) with EC-ElGamal encryption.

    Interface intentionally mirrors RSACipher in rsa_scratch.py so
    crypto_core/encryption_service.py can treat the two interchangeably:
    generate_keypair() / encrypt(plaintext, public_key) /
    decrypt(ciphertext, private_key).
    """

    @staticmethod
    def generate_keypair() -> ECCKeyPair:
        private_key = _random_scalar()
        public_key = _scalar_mult(private_key, _G)
        return ECCKeyPair(public_key=public_key, private_key=private_key)

    @staticmethod
    def encrypt(plaintext: bytes, public_key: tuple) -> bytes:
        if isinstance(plaintext, str):
            raise TypeError("plaintext must be bytes, not str")
        if not is_on_curve(public_key) or public_key is _INFINITY:
            # Rejecting off-curve public keys matters: feeding a point from a
            # different (weaker) curve into scalar multiplication is how
            # invalid-curve attacks recover the private scalar.
            raise ValueError("public key is not a valid point on the curve")

        framed = len(plaintext).to_bytes(_LENGTH_HEADER, "big") + plaintext
        padding = (-len(framed)) % _CHUNK_SIZE
        framed += b"\x00" * padding

        out = bytearray()
        for i in range(0, len(framed), _CHUNK_SIZE):
            message_point = _encode_point(framed[i:i + _CHUNK_SIZE])
            k = _random_scalar()  # fresh ephemeral scalar per block
            c1 = _scalar_mult(k, _G)
            c2 = _point_add(message_point, _scalar_mult(k, public_key))
            out += _compress_point(c1) + _compress_point(c2)
        return bytes(out)

    @staticmethod
    def decrypt(ciphertext: bytes, private_key: int) -> bytes:
        block_size = _POINT_BYTES * 2
        if not ciphertext or len(ciphertext) % block_size != 0:
            raise ValueError("ciphertext length is not a whole number of ECC blocks")

        recovered = bytearray()
        for i in range(0, len(ciphertext), block_size):
            c1 = _decompress_point(ciphertext[i:i + _POINT_BYTES])
            c2 = _decompress_point(ciphertext[i + _POINT_BYTES:i + block_size])
            # M = C2 - d*C1
            shared = _scalar_mult(private_key, c1)
            message_point = _point_add(c2, _point_negate(shared))
            if message_point is _INFINITY:
                raise ValueError("decryption failed (recovered the point at infinity)")
            recovered += _decode_point(message_point)

        if len(recovered) < _LENGTH_HEADER:
            raise ValueError("decrypted data is too short to contain its length header")
        length = int.from_bytes(recovered[:_LENGTH_HEADER], "big")
        body = recovered[_LENGTH_HEADER:]
        if length > len(body):
            raise ValueError("decrypted length header does not match the payload (wrong key?)")
        return bytes(body[:length])
