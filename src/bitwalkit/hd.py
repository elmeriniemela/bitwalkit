"""High-level, watch-only address derivation from account extended keys.

An ``Account`` wraps a single account-level extended public key (e.g. a ``zpub``
at ``m/84'/0'/0'``) and hands out receive/change addresses at the standard
``/{change}/{index}`` suffix. ``MultisigAccount`` does the same for an
``m``-of-``n`` cosigner set, BIP67-sorting the derived keys.

This replaces the ``btclib`` derive + ``ScriptPubKey`` usage in the Odoo
``bitcoin_treasury`` wallet.
"""

from __future__ import annotations

from .address import address_from_pubkey, address_from_script, p2ms_script
from .bip32 import ExtendedKey
from .errors import DerivationError

__all__ = ["Account", "MultisigAccount"]

# Which multisig wrappings are valid, and the single-key types.
_SINGLE_SIG = {"p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"}
_MULTISIG = {"p2wsh", "p2sh-p2wsh", "p2sh"}


class Account:
    """A single-key account: derive addresses from one account xpub."""

    def __init__(self, xpub, script_type: str | None = None):
        self.key = xpub if isinstance(xpub, ExtendedKey) else ExtendedKey.parse(xpub)
        self.script_type = script_type or self.key.script_type_hint
        if self.script_type not in _SINGLE_SIG:
            raise DerivationError(
                f"{self.script_type!r} is not a single-key script type"
            )
        self.network = self.key.network

    def pubkey(self, change: int, index: int) -> bytes:
        """Compressed public key at ``/{change}/{index}``."""
        return self.key.child(change).child(index).pubkey

    def address(self, change: int, index: int) -> str:
        """Address at ``/{change}/{index}``."""
        return address_from_pubkey(self.pubkey(change, index), self.script_type, self.network)

    def receive_address(self, index: int) -> str:
        return self.address(0, index)

    def change_address(self, index: int) -> str:
        return self.address(1, index)

    def addresses(self, change: int, count: int, start: int = 0) -> list[str]:
        """A run of ``count`` addresses on the given ``change`` branch."""
        branch = self.key.child(change)
        return [
            address_from_pubkey(branch.child(i).pubkey, self.script_type, self.network)
            for i in range(start, start + count)
        ]


class MultisigAccount:
    """An ``m``-of-``n`` account: derive addresses from several cosigner xpubs."""

    def __init__(self, xpubs, m: int, script_type: str = "p2wsh", sort: bool = True):
        self.keys = [x if isinstance(x, ExtendedKey) else ExtendedKey.parse(x) for x in xpubs]
        if not self.keys:
            raise DerivationError("multisig needs at least one cosigner key")
        self.m = m
        self.n = len(self.keys)
        if not (1 <= m <= self.n <= 16):
            raise DerivationError(f"invalid multisig {m}-of-{self.n}")
        if script_type not in _MULTISIG:
            raise DerivationError(f"{script_type!r} is not a multisig script type")
        self.script_type = script_type
        self.sort = sort
        self.network = self.keys[0].network

    def witness_script(self, change: int, index: int) -> bytes:
        """The bare ``m``-of-``n`` script at ``/{change}/{index}`` (BIP67-sorted)."""
        pubkeys = [k.child(change).child(index).pubkey for k in self.keys]
        if self.sort:
            pubkeys.sort()  # BIP67: lexicographic on compressed pubkeys
        return p2ms_script(self.m, pubkeys)

    def address(self, change: int, index: int) -> str:
        return address_from_script(self.witness_script(change, index), self.script_type, self.network)

    def receive_address(self, index: int) -> str:
        return self.address(0, index)

    def change_address(self, index: int) -> str:
        return self.address(1, index)

    def addresses(self, change: int, count: int, start: int = 0) -> list[str]:
        return [self.address(change, i) for i in range(start, start + count)]
