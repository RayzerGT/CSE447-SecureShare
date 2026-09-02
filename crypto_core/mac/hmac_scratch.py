"""
crypto_core/mac/hmac_scratch.py
Assigned to: Mos. Mahabuba Akter Munia (see todo.txt)

REQUIREMENT (CSE447 Project.pdf): "Message Authentication Codes (MAC) such as
CBC-MAC or HMAC must verify data integrity and detect unauthorized
modifications." Implement from scratch - do not import `hmac`/`hashlib` and
call it a day; build the construction (and, ideally, the underlying hash or
block cipher) yourself, or clearly document which primitive you're allowed
to build on per your instructor's rules.

TODO(Mos. Mahabuba Akter Munia):
    1. Implement a hash function (or reuse a from-scratch block cipher for
       CBC-MAC) as the primitive.
    2. Implement `compute_mac` / `verify_mac` below.
    3. Call this from your own encryption_service.py to tag encrypted posts/
       messages/profile data, and check the tag on read.
"""


def compute_mac(data: bytes, key: bytes) -> bytes:
    raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): implement MAC (HMAC/CBC-MAC) from scratch.")


def verify_mac(data: bytes, key: bytes, mac_tag: bytes) -> bool:
    raise NotImplementedError("TODO(Mos. Mahabuba Akter Munia): implement MAC verification from scratch.")
