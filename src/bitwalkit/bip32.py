"""Watch-only BIP32 derivation with SLIP-0132 public-key prefixes.

Parse an extended public key (xpub, ypub, zpub, and their multisig or testnet
variants) and derive non-hardened child public keys. Private extended keys are
deliberately rejected so wallet monitoring code cannot ingest signing material.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._secp import G, GE
from .encoding import base58check_decode, base58check_encode
from .errors import DerivationError, EncodingError
from .hashing import hash160, hmac_sha512

__all__ = [
    "ExtendedKey",
    "HARDENED",
    "SCRIPT_TYPES",
]

HARDENED = 0x80000000
_ORDER = GE.ORDER

# Script-type identifiers used across bitwalkit.
SCRIPT_TYPES = ("p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2wsh", "p2sh-p2wsh", "p2tr")

# SLIP-0132 public version bytes -> (network, default script-type hint).
# xpub/tpub are shared by BIP44 (p2pkh) and BIP86 (p2tr); the hint is p2pkh and
# callers that mean taproot pass script_type="p2tr" explicitly.
_VERSIONS: dict[int, tuple[str, str]] = {
    # mainnet public
    0x0488B21E: ("mainnet", "p2pkh"),        # xpub  BIP44
    0x049D7CB2: ("mainnet", "p2sh-p2wpkh"),  # ypub  BIP49
    0x04B24746: ("mainnet", "p2wpkh"),       # zpub  BIP84
    0x0295B43F: ("mainnet", "p2sh-p2wsh"),   # Ypub  BIP48/1 multisig
    0x02AA7ED3: ("mainnet", "p2wsh"),        # Zpub  BIP48/2 multisig
    # testnet public
    0x043587CF: ("testnet", "p2pkh"),         # tpub
    0x044A5262: ("testnet", "p2sh-p2wpkh"),   # upub
    0x045F1CF6: ("testnet", "p2wpkh"),        # vpub
    0x024289EF: ("testnet", "p2sh-p2wsh"),    # Upub
    0x02575483: ("testnet", "p2wsh"),         # Vpub
}

# Recognized only to provide a clear watch-only error instead of a generic
# unknown-version failure. No private-key parsing or derivation is implemented.
_PRIVATE_VERSIONS = {
    0x0488ADE4, 0x049D7878, 0x04B2430C, 0x0295B005, 0x02AA7A99,
    0x04358394, 0x044A4E28, 0x045F18BC, 0x024285B5, 0x02575048,
}


@dataclass(frozen=True)
class ExtendedKey:
    """A parsed BIP32 extended public key."""

    version: int
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    key: bytes  # 33-byte compressed public key
    network: str
    script_type_hint: str

    @classmethod
    def parse(cls, s: str) -> "ExtendedKey":
        """Parse an xpub/ypub/zpub-style string into an ``ExtendedKey``."""
        raw = base58check_decode(s)
        if len(raw) != 78:
            raise EncodingError(f"extended key must be 78 bytes, got {len(raw)}")
        version = int.from_bytes(raw[0:4], "big")
        if version in _PRIVATE_VERSIONS:
            raise EncodingError("private extended keys are not supported")
        meta = _VERSIONS.get(version)
        if meta is None:
            raise EncodingError(f"unknown extended-key version {version:#010x}")
        network, hint = meta
        key = raw[45:78]
        if key[0] not in (0x02, 0x03):
            raise EncodingError("public extended key must be a compressed point")
        try:
            GE.from_bytes_compressed(key)
        except ValueError as exc:
            raise EncodingError("invalid public key point") from exc
        return cls(
            version=version,
            depth=raw[4],
            parent_fingerprint=raw[5:9],
            child_number=int.from_bytes(raw[9:13], "big"),
            chain_code=raw[13:45],
            key=key,
            network=network,
            script_type_hint=hint,
        )

    @property
    def pubkey(self) -> bytes:
        """Compressed public key (33 bytes)."""
        return self.key

    @property
    def identifier(self) -> bytes:
        """HASH160 of the public key."""
        return hash160(self.pubkey)

    @property
    def fingerprint(self) -> bytes:
        """First four bytes of this key's identifier."""
        return self.identifier[:4]

    def serialize(self) -> str:
        """Re-encode this public key with its current extended-key prefix."""
        raw = (
            self.version.to_bytes(4, "big")
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_number.to_bytes(4, "big")
            + self.chain_code
            + self.key
        )
        return base58check_encode(raw)

    def to_xpub(self) -> str:
        """Serialize this key with the canonical xpub/tpub public version."""
        version = 0x0488B21E if self.network == "mainnet" else 0x043587CF
        return ExtendedKey(
            version=version,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            chain_code=self.chain_code,
            key=self.key,
            network=self.network,
            script_type_hint="p2pkh",
        ).serialize()

    def child(self, index: int) -> "ExtendedKey":
        """Derive a non-hardened child public key at ``index``."""
        if not isinstance(index, int) or not 0 <= index <= 0xFFFFFFFF:
            raise DerivationError(f"index out of range: {index!r}")
        if self.depth == 0xFF:
            raise DerivationError("maximum BIP32 depth reached")
        if index >= HARDENED:
            raise DerivationError("cannot derive a hardened child from a public key")

        data = self.key + index.to_bytes(4, "big")
        i = hmac_sha512(self.chain_code, data)
        il = int.from_bytes(i[:32], "big")
        if il >= _ORDER:
            raise DerivationError("derived IL >= curve order; try next index")
        point = (il * G) + GE.from_bytes_compressed(self.key)
        if point.infinity:
            raise DerivationError("derived point at infinity; try next index")

        return ExtendedKey(
            version=self.version,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
            chain_code=i[32:],
            key=point.to_bytes_compressed(),
            network=self.network,
            script_type_hint=self.script_type_hint,
        )

    def derive_path(self, path) -> "ExtendedKey":
        """Derive along a relative path.

        ``path`` may be a string such as ``"0/5"`` or an iterable of integer
        indexes. A leading ``m/`` is accepted and ignored. Hardened path steps
        are parsed so they can produce the standard public-derivation error.
        """
        node = self
        for index in _parse_path(path):
            node = node.child(index)
        return node


def _parse_path(path):
    if isinstance(path, str):
        parts = path.strip().split("/")
    else:
        parts = path
    for position, part in enumerate(parts):
        if isinstance(part, int):
            if not 0 <= part <= 0xFFFFFFFF:
                raise DerivationError(f"index out of range: {part}")
            yield part
            continue
        if position == 0 and part in ("m", "M", ""):
            continue
        if not part:
            continue
        hardened = part[-1] in ("'", "h", "H")
        value = part[:-1] if hardened else part
        if not value.isdigit():
            raise DerivationError(f"invalid path step: {part!r}")
        number = int(value)
        if number >= HARDENED:
            raise DerivationError(f"index out of range: {part}")
        yield number + (HARDENED if hardened else 0)
