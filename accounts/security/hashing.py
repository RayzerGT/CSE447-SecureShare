import os
import struct

from django.contrib.auth.hashers import BasePasswordHasher, mask_hash
from django.utils.translation import gettext_noop as _t

_MASK32 = 0xFFFFFFFF

_SALT_BYTES = 16
_DEFAULT_ITERATIONS = 1_000
_ALGORITHM_TAG = "scratchsha256"

_K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

_H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32

def _sha256(message: bytes) -> bytes:
    msg_len_bits = len(message) * 8
    padded = message + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += struct.pack(">Q", msg_len_bits)

    h = list(_H0)

    for offset in range(0, len(padded), 64):
        w = list(struct.unpack(">16I", padded[offset:offset + 64])) + [0] * 48
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32

        a, b, c, d, e, f, g, hh = h

        for i in range(64):
            big_s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (hh + big_s1 + ch + _K[i] + w[i]) & _MASK32
            big_s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (big_s0 + maj) & _MASK32

            hh, g, f = g, f, e
            e = (d + temp1) & _MASK32
            d, c, b = c, b, a
            a = (temp1 + temp2) & _MASK32

        h = [(x + y) & _MASK32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]

    return struct.pack(">8I", *h)

def _stretch(password: bytes, salt: bytes, iterations: int) -> bytes:
    block = _sha256(salt + password)
    for _ in range(iterations - 1):
        block = _sha256(block + password + salt)
    return block

def _constant_time_equals(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

def generate_salt() -> str:
    return os.urandom(_SALT_BYTES).hex()

def hash_password(plain_password: str, salt: str, iterations: int = _DEFAULT_ITERATIONS) -> str:
    digest = _stretch(plain_password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return f"{_ALGORITHM_TAG}${iterations}${salt}${digest.hex()}"

def verify_password(plain_password: str, salt: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_str, stored_salt, _digest_hex = stored_hash.split("$")
    except ValueError:
        return False
    if algorithm != _ALGORITHM_TAG or stored_salt != salt:
        return False
    expected = hash_password(plain_password, salt, int(iterations_str))
    return _constant_time_equals(expected.encode("utf-8"), stored_hash.encode("utf-8"))

class FromScratchPasswordHasher(BasePasswordHasher):

    algorithm = _ALGORITHM_TAG

    def salt(self) -> str:
        return generate_salt()

    def encode(self, password: str, salt: str) -> str:
        return hash_password(password, salt)

    def decode(self, encoded: str) -> dict:
        algorithm, iterations, salt, digest_hex = encoded.split("$")
        return {
            "algorithm": algorithm,
            "iterations": int(iterations),
            "salt": salt,
            "hash": digest_hex,
        }

    def verify(self, password: str, encoded: str) -> bool:
        try:
            decoded = self.decode(encoded)
        except ValueError:
            return False
        return verify_password(password, decoded["salt"], encoded)

    def safe_summary(self, encoded: str) -> dict:
        decoded = self.decode(encoded)
        return {
            _t("algorithm"): decoded["algorithm"],
            _t("iterations"): decoded["iterations"],
            _t("salt"): mask_hash(decoded["salt"]),
            _t("hash"): mask_hash(decoded["hash"]),
        }

    def must_update(self, encoded: str) -> bool:
        return self.decode(encoded)["iterations"] != _DEFAULT_ITERATIONS

    def harden_runtime(self, password: str, encoded: str) -> None:
        decoded = self.decode(encoded)
        extra_iterations = _DEFAULT_ITERATIONS - decoded["iterations"]
        if extra_iterations > 0:
            hash_password(password, decoded["salt"], extra_iterations)
