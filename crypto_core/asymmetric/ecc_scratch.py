import os
from dataclasses import dataclass

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

_G = (_GX, _GY)

_COORD_BYTES = 32
_POINT_BYTES = 33
_KOBLITZ_K = 1024
_CHUNK_SIZE = 30
_LENGTH_HEADER = 4

_INFINITY = None

@dataclass
class ECCKeyPair:
    public_key: tuple
    private_key: int

def _mod_inverse(a: int, m: int = _P) -> int:
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
    a %= _P
    if a == 0:
        return 0
    root = pow(a, (_P + 1) // 4, _P)
    if (root * root) % _P != a:
        raise ValueError("value is not a quadratic residue mod p")
    return root

def _curve_rhs(x: int) -> int:
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
    if p1 is _INFINITY:
        return p2
    if p2 is _INFINITY:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and (y1 + y2) % _P == 0:
        return _INFINITY

    if p1 == p2:
        slope = (3 * x1 * x1 + _A) * _mod_inverse(2 * y1) % _P
    else:
        slope = (y2 - y1) * _mod_inverse(x2 - x1) % _P

    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return (x3, y3)

def _scalar_mult(k: int, point):
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
    while True:
        candidate = int.from_bytes(os.urandom(_COORD_BYTES), "big")
        if 1 <= candidate < _N:
            return candidate

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
    if (y & 1) != (data[0] & 1):
        y = (-y) % _P
    point = (x, y)
    if not is_on_curve(point):
        raise ValueError("decompressed point is not on the curve")
    return point

def _encode_point(chunk: bytes):
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
            continue
        return (x, y)
    raise ValueError("failed to embed chunk on the curve (should be practically impossible)")

def _decode_point(point) -> bytes:
    x, _ = point
    m = x // _KOBLITZ_K
    try:
        return m.to_bytes(_CHUNK_SIZE, "big")
    except OverflowError:
        raise ValueError("decryption failed (recovered point does not decode - wrong key?)") from None

class ECCCipher:

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
            raise ValueError("public key is not a valid point on the curve")

        framed = len(plaintext).to_bytes(_LENGTH_HEADER, "big") + plaintext
        padding = (-len(framed)) % _CHUNK_SIZE
        framed += b"\x00" * padding

        out = bytearray()
        for i in range(0, len(framed), _CHUNK_SIZE):
            message_point = _encode_point(framed[i:i + _CHUNK_SIZE])
            k = _random_scalar()
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
