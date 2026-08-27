"""Bitcoin Core output-descriptor checksums."""

from .errors import EncodingError

__all__ = ["descriptor_checksum"]

_INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
_CHECKSUM = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(checksum: int, value: int) -> int:
    top = checksum >> 35
    checksum = ((checksum & 0x7FFFFFFFF) << 5) ^ value
    for bit, generator in enumerate(
        (0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD)
    ):
        if top >> bit & 1:
            checksum ^= generator
    return checksum


def descriptor_checksum(descriptor: str) -> str:
    """Return the eight-character checksum used after ``#`` in descriptors."""
    checksum = 1
    group = count = 0
    for character in descriptor:
        position = _INPUT.find(character)
        if position < 0:
            raise EncodingError(f"unsupported descriptor character: {character!r}")
        checksum = _polymod(checksum, position & 31)
        group = group * 3 + (position >> 5)
        count += 1
        if count == 3:
            checksum = _polymod(checksum, group)
            group = count = 0
    if count:
        checksum = _polymod(checksum, group)
    for _ in range(8):
        checksum = _polymod(checksum, 0)
    checksum ^= 1
    return "".join(_CHECKSUM[(checksum >> (5 * (7 - index))) & 31] for index in range(8))
