"""Address encodings: Base58Check (P2PKH / P2SH) and bech32 / bech32m (segwit).

The encoders are adapted from the pure-Python ``bitoplens`` library (which only
needed the script -> address direction). The matching decoders (address ->
payload), required to turn a user-supplied address into a scriptPubKey, are
added here. Implements BIP173 (bech32) and BIP350 (bech32m).
"""

from __future__ import annotations

from .errors import EncodingError
from .hashing import hash256

__all__ = [
    "base58check_encode",
    "base58check_decode",
    "bech32_encode",
    "bech32_decode",
    "convertbits",
]

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INV = {c: i for i, c in enumerate(_B58)}
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_CHARSET_INV = {c: i for i, c in enumerate(_CHARSET)}

BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


# --------------------------------------------------------------------------- #
# Base58Check
# --------------------------------------------------------------------------- #

def base58check_encode(payload: bytes) -> str:
    """Base58Check-encode ``payload`` (version byte(s) + data)."""
    checksum = hash256(payload)[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    # Preserve leading zero bytes as '1'.
    for b in data:
        if b == 0:
            out = "1" + out
        else:
            break
    return out


def base58check_decode(s: str) -> bytes:
    """Decode a Base58Check string and return the payload (checksum stripped).

    Raises :class:`EncodingError` on unknown characters or a bad checksum.
    """
    if not s:
        raise EncodingError("empty base58 string")
    n = 0
    for ch in s:
        try:
            n = n * 58 + _B58_INV[ch]
        except KeyError:
            raise EncodingError(f"invalid base58 character: {ch!r}") from None
    # Reconstruct big-endian bytes, then restore the leading zero bytes ('1's).
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    data = b"\x00" * pad + body
    if len(data) < 4:
        raise EncodingError("base58 string too short for a checksum")
    payload, checksum = data[:-4], data[-4:]
    if hash256(payload)[:4] != checksum:
        raise EncodingError("bad base58 checksum")
    return payload


# --------------------------------------------------------------------------- #
# bech32 / bech32m (BIP173 / BIP350)
# --------------------------------------------------------------------------- #

def _polymod(values) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= generators[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def convertbits(data, frombits, tobits, pad=True):
    """Repack a bit stream from groups of ``frombits`` to groups of ``tobits``.

    Returns ``None`` if the input is invalid (out-of-range value, or leftover
    bits when ``pad`` is False) -- matching the BIP173 reference behaviour.
    """
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, witver: int, program: bytes) -> str:
    """Encode a segwit address (bech32 for v0, bech32m for v1+)."""
    packed = convertbits(program, 8, 5)
    if packed is None:
        raise EncodingError("invalid witness program bytes")
    data = [witver] + packed
    const = BECH32_CONST if witver == 0 else BECH32M_CONST
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in data + checksum)


def bech32_decode(addr: str) -> tuple[str, int, bytes]:
    """Decode a segwit address into ``(hrp, witness_version, program)``.

    Validates the bech32/bech32m checksum against the witness version (BIP173
    for v0, BIP350 for v1+), rejects mixed case, and enforces the segwit
    program length rules. Raises :class:`EncodingError` on any failure.
    """
    if addr != addr.lower() and addr != addr.upper():
        raise EncodingError("mixed-case bech32 string")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise EncodingError("invalid bech32 separator position")
    hrp = addr[:pos]
    try:
        data = [_CHARSET_INV[c] for c in addr[pos + 1 :]]
    except KeyError as exc:
        raise EncodingError(f"invalid bech32 character: {exc.args[0]!r}") from None

    const = _polymod(_hrp_expand(hrp) + data)
    if const == BECH32_CONST:
        spec_witver_max = 0
    elif const == BECH32M_CONST:
        spec_witver_max = 16
    else:
        raise EncodingError("bad bech32 checksum")

    witver = data[0]
    program = convertbits(data[1:-6], 5, 8, False)
    if program is None or not (2 <= len(program) <= 40):
        raise EncodingError("invalid bech32 program length")
    if witver > 16:
        raise EncodingError("invalid witness version")
    if witver == 0 and len(program) not in (20, 32):
        raise EncodingError("invalid v0 witness program length")
    # Checksum constant must match the witness version (BIP350).
    if (witver == 0) != (spec_witver_max == 0):
        raise EncodingError("wrong bech32 constant for witness version")

    return hrp, witver, bytes(program)
