"""Hash primitives used throughout Bitcoin key, script and address handling.

All functions take and return ``bytes``. ``ripemd160`` falls back to a
pure-Python implementation because ``hashlib`` only offers RIPEMD-160 when the
underlying OpenSSL build enables it, which modern distributions increasingly do
not -- yet HASH160 (used by P2PKH / P2WPKH / P2SH) needs it.

Copied from the pure-Python ``bitoplens`` library so that bitwalkit stays
dependency-free.
"""

from __future__ import annotations

import hashlib
import hmac

__all__ = [
    "sha256",
    "hash256",
    "ripemd160",
    "hash160",
    "tagged_hash",
    "hmac_sha512",
]


def sha256(data: bytes) -> bytes:
    """Single SHA-256."""
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Double SHA-256 (``SHA256(SHA256(data))``) -- Bitcoin's ``Hash``."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160, via ``hashlib`` when available else a pure-Python fallback."""
    try:
        h = hashlib.new("ripemd160")
    except (ValueError, TypeError):  # OpenSSL without the legacy provider
        return _ripemd160_pure(data)
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    """``RIPEMD160(SHA256(data))`` -- Bitcoin's ``Hash160``."""
    return ripemd160(sha256(data))


def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP340 tagged hash: ``SHA256(SHA256(tag) || SHA256(tag) || data)``.

    Used for TapTweak (BIP341/BIP86 taproot output keys) and Schnorr.
    """
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def hmac_sha512(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA512 -- the PRF used by BIP32 child key derivation."""
    return hmac.new(key, data, hashlib.sha512).digest()


# --------------------------------------------------------------------------- #
# Pure-Python RIPEMD-160 fallback (public domain reference algorithm).
# --------------------------------------------------------------------------- #

def _rol(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


# Message word selection per round, left and right lines.
_RL = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
    (7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8),
    (3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12),
    (1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2),
    (4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13),
)
_RR = (
    (5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12),
    (6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2),
    (15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13),
    (8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14),
    (12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11),
)
# Per-round rotate amounts, left and right lines.
_SL = (
    (11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8),
    (7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12),
    (11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5),
    (11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12),
    (9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6),
)
_SR = (
    (8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6),
    (9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11),
    (9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5),
    (15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8),
    (8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11),
)
_KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)


def _f(j: int, x: int, y: int, z: int) -> int:
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def _ripemd160_pure(message: bytes) -> bytes:
    h0, h1, h2, h3, h4 = (
        0x67452301,
        0xEFCDAB89,
        0x98BADCFE,
        0x10325476,
        0xC3D2E1F0,
    )
    # Padding: 0x80, zeros, then 64-bit little-endian bit length.
    ml = len(message) * 8
    message = message + b"\x80"
    message += b"\x00" * ((56 - len(message) % 64) % 64)
    message += (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")

    for off in range(0, len(message), 64):
        block = message[off : off + 64]
        x = [int.from_bytes(block[i : i + 4], "little") for i in range(0, 64, 4)]
        al, bl, cl, dl, el = h0, h1, h2, h3, h4
        ar, br, cr, dr, er = h0, h1, h2, h3, h4
        for rnd in range(5):
            for i in range(16):
                j = rnd * 16 + i
                t = _rol((al + _f(j, bl, cl, dl) + x[_RL[rnd][i]] + _KL[rnd]) & 0xFFFFFFFF, _SL[rnd][i])
                t = (t + el) & 0xFFFFFFFF
                al, bl, cl, dl, el = el, t, bl, _rol(cl, 10), dl
                jr = (79 - j)
                t = _rol((ar + _f(jr, br, cr, dr) + x[_RR[rnd][i]] + _KR[rnd]) & 0xFFFFFFFF, _SR[rnd][i])
                t = (t + er) & 0xFFFFFFFF
                ar, br, cr, dr, er = er, t, br, _rol(cr, 10), dr
        t = (h1 + cl + dr) & 0xFFFFFFFF
        h1 = (h2 + dl + er) & 0xFFFFFFFF
        h2 = (h3 + el + ar) & 0xFFFFFFFF
        h3 = (h4 + al + br) & 0xFFFFFFFF
        h4 = (h0 + bl + cr) & 0xFFFFFFFF
        h0 = t

    return b"".join(v.to_bytes(4, "little") for v in (h0, h1, h2, h3, h4))
