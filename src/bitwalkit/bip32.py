"""BIP32 hierarchical-deterministic keys, with SLIP-0132 extended-key prefixes.

The public API is watch-only: parse a master/account extended *public* key
(xpub / ypub / zpub / ...) and derive child public keys along the standard
``.../{change}/{index}`` suffix. Private extended keys (xprv / ...) are also
accepted -- their public key and hardened children can be derived -- but
bitwalkit never signs, so no private material leaves this module.

Replaces the slivers of ``btclib`` that the Odoo code used:
``btclib.to_pub_key.fingerprint`` and ``btclib.bip32.derive``.
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

# SLIP-0132 version bytes -> (network, default script-type hint, is_private).
# xpub/tpub are shared by BIP44 (p2pkh) and BIP86 (p2tr); the hint is p2pkh and
# callers that mean taproot pass script_type="p2tr" explicitly.
_VERSIONS: dict[int, tuple[str, str, bool]] = {
    # mainnet public
    0x0488B21E: ("mainnet", "p2pkh", False),        # xpub  BIP44
    0x049D7CB2: ("mainnet", "p2sh-p2wpkh", False),  # ypub  BIP49
    0x04B24746: ("mainnet", "p2wpkh", False),        # zpub  BIP84
    0x0295B43F: ("mainnet", "p2sh-p2wsh", False),    # Ypub  BIP48/1 multisig
    0x02AA7ED3: ("mainnet", "p2wsh", False),         # Zpub  BIP48/2 multisig
    # mainnet private
    0x0488ADE4: ("mainnet", "p2pkh", True),          # xprv
    0x049D7878: ("mainnet", "p2sh-p2wpkh", True),    # yprv
    0x04B2430C: ("mainnet", "p2wpkh", True),         # zprv
    0x0295B005: ("mainnet", "p2sh-p2wsh", True),     # Yprv
    0x02AA7A99: ("mainnet", "p2wsh", True),          # Zprv
    # testnet public
    0x043587CF: ("testnet", "p2pkh", False),         # tpub
    0x044A5262: ("testnet", "p2sh-p2wpkh", False),   # upub
    0x045F1CF6: ("testnet", "p2wpkh", False),        # vpub
    0x024289EF: ("testnet", "p2sh-p2wsh", False),    # Upub
    0x02575483: ("testnet", "p2wsh", False),         # Vpub
    # testnet private
    0x04358394: ("testnet", "p2pkh", True),          # tprv
    0x044A4E28: ("testnet", "p2sh-p2wpkh", True),    # uprv
    0x045F18BC: ("testnet", "p2wpkh", True),         # vprv
    0x024285B5: ("testnet", "p2sh-p2wsh", True),     # Uprv
    0x02575048: ("testnet", "p2wsh", True),          # Vprv
}


def _pubkey_from_secret(secret: bytes) -> bytes:
    """Compressed public key for a 32-byte private key."""
    k = int.from_bytes(secret, "big")
    if not (0 < k < _ORDER):
        raise DerivationError("private key out of range")
    return (k * G).to_bytes_compressed()


@dataclass(frozen=True)
class ExtendedKey:
    """A parsed BIP32 extended key (public or private)."""

    version: int
    depth: int
    parent_fingerprint: bytes
    child_number: int
    chain_code: bytes
    key: bytes  # 33 bytes: compressed pubkey, or 0x00 || 32-byte privkey
    network: str
    script_type_hint: str
    is_private: bool

    # -- construction ------------------------------------------------------ #

    @classmethod
    def parse(cls, s: str) -> "ExtendedKey":
        """Parse a base58 xpub/xprv/ypub/... string into an ``ExtendedKey``."""
        raw = base58check_decode(s)
        if len(raw) != 78:
            raise EncodingError(f"extended key must be 78 bytes, got {len(raw)}")
        version = int.from_bytes(raw[0:4], "big")
        meta = _VERSIONS.get(version)
        if meta is None:
            raise EncodingError(f"unknown extended-key version {version:#010x}")
        network, hint, is_private = meta
        key = raw[45:78]
        if is_private:
            if key[0] != 0x00 or not 0 < int.from_bytes(key[1:], "big") < _ORDER:
                raise EncodingError("private extended key must start with 0x00")
        elif key[0] not in (0x02, 0x03):
            raise EncodingError("public extended key must be a compressed point")
        else:
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
            is_private=is_private,
        )

    # -- properties -------------------------------------------------------- #

    @property
    def pubkey(self) -> bytes:
        """Compressed public key (33 bytes)."""
        if self.is_private:
            return _pubkey_from_secret(self.key[1:])
        return self.key

    @property
    def identifier(self) -> bytes:
        """HASH160 of the public key."""
        return hash160(self.pubkey)

    @property
    def fingerprint(self) -> bytes:
        """First 4 bytes of the identifier (this key's own fingerprint)."""
        return self.identifier[:4]

    # -- serialization ----------------------------------------------------- #

    def serialize(self) -> str:
        """Re-encode to a base58 extended-key string."""
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
        key = self.neuter()
        version = 0x0488B21E if key.network == "mainnet" else 0x043587CF
        return ExtendedKey(
            version=version,
            depth=key.depth,
            parent_fingerprint=key.parent_fingerprint,
            child_number=key.child_number,
            chain_code=key.chain_code,
            key=key.key,
            network=key.network,
            script_type_hint="p2pkh",
            is_private=False,
        ).serialize()

    def neuter(self) -> "ExtendedKey":
        """Return the public (xpub-style) counterpart of this key."""
        if not self.is_private:
            return self
        pub_version = _to_public_version(self.version)
        return ExtendedKey(
            version=pub_version,
            depth=self.depth,
            parent_fingerprint=self.parent_fingerprint,
            child_number=self.child_number,
            chain_code=self.chain_code,
            key=self.pubkey,
            network=self.network,
            script_type_hint=self.script_type_hint,
            is_private=False,
        )

    # -- derivation -------------------------------------------------------- #

    def child(self, index: int) -> "ExtendedKey":
        """Derive the child key at ``index`` (add ``HARDENED`` for a hardened step)."""
        if not isinstance(index, int) or not 0 <= index <= 0xFFFFFFFF:
            raise DerivationError(f"index out of range: {index!r}")
        if self.depth == 0xFF:
            raise DerivationError("maximum BIP32 depth reached")
        hardened = index >= HARDENED
        if hardened and not self.is_private:
            raise DerivationError(
                "cannot derive a hardened child from a public key"
            )
        if self.is_private:
            secret = self.key[1:]
            if hardened:
                data = b"\x00" + secret + index.to_bytes(4, "big")
            else:
                data = self.pubkey + index.to_bytes(4, "big")
            i = hmac_sha512(self.chain_code, data)
            il = int.from_bytes(i[:32], "big")
            if il >= _ORDER:
                raise DerivationError("derived IL >= curve order; try next index")
            child_secret = (il + int.from_bytes(secret, "big")) % _ORDER
            if child_secret == 0:
                raise DerivationError("derived zero private key; try next index")
            child_key = b"\x00" + child_secret.to_bytes(32, "big")
        else:
            data = self.key + index.to_bytes(4, "big")
            i = hmac_sha512(self.chain_code, data)
            il = int.from_bytes(i[:32], "big")
            if il >= _ORDER:
                raise DerivationError("derived IL >= curve order; try next index")
            point = (il * G) + GE.from_bytes_compressed(self.key)
            if point.infinity:
                raise DerivationError("derived point at infinity; try next index")
            child_key = point.to_bytes_compressed()

        return ExtendedKey(
            version=self.version,
            depth=self.depth + 1,
            parent_fingerprint=self.fingerprint,
            child_number=index,
            chain_code=i[32:],
            key=child_key,
            network=self.network,
            script_type_hint=self.script_type_hint,
            is_private=self.is_private,
        )

    def derive_path(self, path) -> "ExtendedKey":
        """Derive along a relative path.

        ``path`` may be a string like ``"0/5"`` or ``"1'/0/5"`` (``'`` or ``h``
        marks a hardened index), or an iterable of ints. A leading ``m/`` is
        accepted and ignored.
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


def _to_public_version(version: int) -> int:
    network, hint, is_private = _VERSIONS[version]
    if not is_private:
        return version
    for ver, (net, cand_hint, priv) in _VERSIONS.items():
        if net == network and cand_hint == hint and not priv:
            return ver
    raise EncodingError("no public version counterpart")
