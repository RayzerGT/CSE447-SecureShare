import os
from dataclasses import dataclass

_PUBLIC_EXPONENT = 65537
_MILLER_RABIN_ROUNDS = 40
_SMALL_PRIMES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)

@dataclass
class RSAKeyPair:
    public_key: tuple
    private_key: tuple

def _is_probable_prime(n: int, rounds: int = _MILLER_RABIN_ROUNDS) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        byte_len = (n.bit_length() + 7) // 8
        a = int.from_bytes(os.urandom(byte_len), "big") % (n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _generate_prime(bits: int) -> int:
    while True:
        candidate = int.from_bytes(os.urandom(bits // 8), "big")
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate

def _extended_gcd(a: int, b: int) -> tuple:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return old_r, old_s, old_t

def _mod_inverse(a: int, m: int) -> int:
    gcd, x, _ = _extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("modular inverse does not exist (a and m are not coprime)")
    return x % m

def _pkcs1_pad(message: bytes, k: int) -> bytes:
    max_len = k - 11
    if len(message) > max_len:
        raise ValueError(f"message too long for a {k * 8}-bit key with this padding (max {max_len} bytes)")
    ps = bytearray()
    while len(ps) < k - len(message) - 3:
        b = os.urandom(1)
        if b != b"\x00":
            ps += b
    return b"\x00\x02" + bytes(ps) + b"\x00" + message

def _pkcs1_unpad(padded: bytes) -> bytes:
    if len(padded) < 11 or padded[0:2] != b"\x00\x02":
        raise ValueError("invalid RSA padding")
    separator_index = padded.index(b"\x00", 2)
    return padded[separator_index + 1:]

class RSACipher:

    @staticmethod
    def generate_keypair(key_size_bits: int = 1024) -> RSAKeyPair:
        half = key_size_bits // 2
        while True:
            p = _generate_prime(half)
            q = _generate_prime(half)
            if p == q:
                continue
            n = p * q
            phi = (p - 1) * (q - 1)
            try:
                d = _mod_inverse(_PUBLIC_EXPONENT, phi)
            except ValueError:
                continue
            return RSAKeyPair(public_key=(_PUBLIC_EXPONENT, n), private_key=(d, n))

    @staticmethod
    def encrypt(plaintext: bytes, public_key: tuple) -> bytes:
        e, n = public_key
        k = (n.bit_length() + 7) // 8
        padded = _pkcs1_pad(plaintext, k)
        m = int.from_bytes(padded, "big")
        c = pow(m, e, n)
        return c.to_bytes(k, "big")

    @staticmethod
    def decrypt(ciphertext: bytes, private_key: tuple) -> bytes:
        d, n = private_key
        k = (n.bit_length() + 7) // 8
        if len(ciphertext) != k:
            raise ValueError("ciphertext length does not match key size")
        c = int.from_bytes(ciphertext, "big")
        m = pow(c, d, n)
        padded = m.to_bytes(k, "big")
        return _pkcs1_unpad(padded)
