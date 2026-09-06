"""Offline PSBT v0 construction from explicitly declared native SegWit inputs.

Amounts are integer satoshis. No chain state is queried or inferred: callers
provide the outpoints, their values, and the wallet derivation information.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import re
from typing import Sequence

from ._secp import GE
from .address import address_from_pubkey, address_from_script, p2ms_script, p2wpkh_script, p2wsh_script
from .bip32 import ExtendedKey, HARDENED
from .encoding import base58check_decode, base58check_encode
from .errors import EncodingError

MAX_MONEY = 21_000_000 * 100_000_000


def _uint(value: int, maximum: int, label: str) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise EncodingError(f"{label} must be an integer between 0 and {maximum}")
    return value


@dataclass(frozen=True)
class KeyOrigin:
    fingerprint: bytes
    path: tuple[int, ...] = ()

    @classmethod
    def parse(cls, fingerprint: str, path: str) -> KeyOrigin:
        """Parse an eight-digit master fingerprint and absolute BIP32 path."""
        if not re.fullmatch(r"[0-9a-fA-F]{8}", fingerprint):
            raise EncodingError("Master key fingerprint must have eight hexadecimal digits")
        if path == "m":
            steps = []
        else:
            value = path[2:] if path.startswith("m/") else path
            steps = value.split("/")
        indexes = []
        for step in steps:
            if not re.fullmatch(r"[0-9]+['hH]?", step):
                raise EncodingError("Enter a complete BIP32 origin path")
            hardened = step[-1] in "'hH"
            index = int(step[:-1] if hardened else step)
            indexes.append(_uint(index, HARDENED - 1, "Path index") + (HARDENED if hardened else 0))
        return cls(bytes.fromhex(fingerprint), tuple(indexes))

    def serialize(self) -> bytes:
        if not isinstance(self.fingerprint, bytes) or len(self.fingerprint) != 4:
            raise EncodingError("Master key fingerprint must be four bytes")
        return self.fingerprint + b"".join(
            _uint(i, 0xFFFFFFFF, "Path index").to_bytes(4, "little") for i in self.path
        )


@dataclass(frozen=True)
class SegwitSpend:
    """Scripts and origins for a particular wallet branch/address index."""

    address: str
    script_pubkey: bytes
    derivations: tuple[tuple[bytes, KeyOrigin], ...]
    xpubs: tuple[tuple[bytes, KeyOrigin], ...]
    witness_script: bytes = b""


def derive_native_segwit(
    keys: Sequence[tuple[ExtendedKey | str, KeyOrigin | None]],
    change: int,
    index: int,
    *,
    threshold: int = 1,
) -> SegwitSpend:
    """Derive P2WPKH or sorted P2WSH signing metadata from account xpubs.

    One key uses P2WPKH; 2..15 keys use P2WSH sortedmulti. Non-master
    extended keys require their full master origin. No address scan is needed.
    """
    _uint(change, 1, "Branch")
    _uint(index, HARDENED - 1, "Address index")
    if not 1 <= len(keys) <= 15:
        raise EncodingError("Use between 1 and 15 extended public keys")
    _uint(threshold, len(keys), "Required signatures")
    if threshold == 0:
        raise EncodingError("At least one signature is required")
    derivations = []
    xpubs = []
    networks = set()
    for value, origin in keys:
        key = ExtendedKey.parse(value) if isinstance(value, str) else value
        networks.add(key.network)
        if key.depth == 0:
            expected = KeyOrigin(key.fingerprint)
            if origin is not None and origin != expected:
                raise EncodingError("Master key origin must use its own fingerprint and path m")
            origin = expected
        elif origin is None:
            raise EncodingError("Add the master fingerprint and full origin path for every account key")
        origin.serialize()
        if len(origin.path) != key.depth:
            raise EncodingError("Origin path depth does not match the extended public key")
        if origin.path and origin.path[-1] != key.child_number:
            raise EncodingError("Origin path's last index does not match the extended public key")
        if key.depth == 1 and origin.fingerprint != key.parent_fingerprint:
            raise EncodingError("Master fingerprint does not match this depth-one key's parent")
        pubkey = key.child(change).child(index).pubkey
        derivations.append((pubkey, KeyOrigin(origin.fingerprint, origin.path + (change, index))))
        xpubs.append((base58check_decode(key.to_xpub()), origin))
    if len(networks) != 1:
        raise EncodingError("Every extended public key must use the same network")
    derivations.sort(key=lambda entry: entry[0])
    pubkeys = [entry[0] for entry in derivations]
    if len(set(pubkeys)) != len(pubkeys):
        raise EncodingError("Duplicate multisig public keys")
    network = networks.pop()
    witness = p2ms_script(threshold, pubkeys) if len(keys) > 1 else b""
    script = p2wsh_script(witness) if witness else p2wpkh_script(pubkeys[0])
    address = (address_from_script(witness, "p2wsh", network) if witness else
               address_from_pubkey(pubkeys[0], "p2wpkh", network))
    return SegwitSpend(address, script, tuple(derivations), tuple(xpubs), witness)


class InputSequence(IntEnum):
    """Common input sequences; arbitrary uint32 integers are also supported.

    All presets disable BIP 68 relative locktime. FINAL bypasses transaction
    locktime when used by every input. LOCKTIME enables transaction locktime
    without explicit BIP 125 signaling; RBF also signals replacement. Neither
    preset sets the transaction's locktime value or version. Lack of explicit
    signaling does not guarantee that a transaction cannot be replaced.

    References: https://bips.dev/125/ and https://bips.dev/68/.
    """

    FINAL = 0xFFFFFFFF
    LOCKTIME = 0xFFFFFFFE
    RBF = 0xFFFFFFFD


@dataclass(frozen=True)
class PSBTInput:
    """A declared outpoint with a named preset or plain uint32 sequence."""

    txid: str
    output_index: int
    amount: int
    spend: SegwitSpend
    sequence: int | InputSequence = InputSequence.FINAL


@dataclass(frozen=True)
class PSBTOutput:
    amount: int
    script_pubkey: bytes
    spend: SegwitSpend | None = None


def _compact_size(value: int) -> bytes:
    for limit, prefix, size in ((253, b"", 1), (0x10000, b"\xfd", 2), (0x100000000, b"\xfe", 4)):
        if value < limit:
            return prefix + value.to_bytes(size, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _blob(value: bytes) -> bytes:
    return _compact_size(len(value)) + value


def _map(entries: list[tuple[bytes, bytes]]) -> bytes:
    result = {}
    for key, value in entries:
        if key in result and result[key] != value:
            raise EncodingError("Conflicting PSBT metadata for the same key")
        result[key] = value
    return b"".join(_blob(key) + _blob(value) for key, value in sorted(result.items())) + b"\x00"


def _txout(amount: int, script: bytes) -> bytes:
    _uint(amount, MAX_MONEY, "Amount in satoshis")
    if not isinstance(script, bytes) or not script:
        raise EncodingError("Output script must be nonempty bytes")
    return amount.to_bytes(8, "little") + _blob(script)


def dust_threshold(script_pubkey: bytes, *, dust_relay_fee: int = 3000) -> int:
    """Bitcoin Core dust threshold in satoshis at a chosen sat/kvB rate.

    This is an advisory policy calculation, not a consensus limit or a live
    relay guarantee. The default baseline is 3000 sat/kvB. Matches Core's
    GetDustThreshold (including its conservative witness spend-size model).
    PSBT construction does not enforce this threshold.
    """
    _uint(dust_relay_fee, MAX_MONEY, "Dust relay fee in sat/kvB")
    if not isinstance(script_pubkey, bytes) or not script_pubkey:
        raise EncodingError("Output script must be nonempty bytes")
    if script_pubkey[0] == 0x6A or len(script_pubkey) > 10_000:
        return 0
    witness = (4 <= len(script_pubkey) <= 42
               and (script_pubkey[0] == 0 or 0x51 <= script_pubkey[0] <= 0x60)
               and script_pubkey[1] == len(script_pubkey) - 2)
    size = 8 + len(_blob(script_pubkey)) + (67 if witness else 148)
    return (size * dust_relay_fee + 999) // 1000


def _metadata(spend: SegwitSpend, *, output: bool = False) -> list[tuple[bytes, bytes]]:
    pubkeys = [pk for pk, _ in spend.derivations]
    if not pubkeys or len(set(pubkeys)) != len(pubkeys):
        raise EncodingError("Signing metadata needs unique public keys")
    for pubkey in pubkeys:
        if not isinstance(pubkey, bytes) or len(pubkey) != 33 or pubkey[0] not in (2, 3):
            raise EncodingError("Native SegWit signing metadata requires compressed public keys")
        try:
            GE.from_bytes_compressed(pubkey)
        except ValueError as error:
            raise EncodingError("Invalid signing public key point") from error
    if spend.witness_script:
        if spend.script_pubkey != p2wsh_script(spend.witness_script):
            raise EncodingError("Witness script does not match the source output")
        # Only the sortedmulti scripts supported by the derivation helper.
        threshold = spend.witness_script[0] - 0x50
        if spend.witness_script != p2ms_script(threshold, sorted(pubkeys)):
            raise EncodingError("Witness script does not match the signing keys")
    elif len(pubkeys) != 1 or spend.script_pubkey != p2wpkh_script(pubkeys[0]):
        raise EncodingError("Single-signature metadata does not match the source output")
    entries = [(bytes([0x02 if output else 0x06]) + pk, origin.serialize())
               for pk, origin in spend.derivations]
    if spend.witness_script:
        entries.append((bytes([0x01 if output else 0x05]), spend.witness_script))
    return entries


def create_psbt(
    inputs: Sequence[PSBTInput],
    outputs: Sequence[PSBTOutput],
    *,
    version: int = 2,
    locktime: int = 0,
) -> bytes:
    """Build a PSBT v0, with SIGHASH_ALL, from declared amounts and origins.

    Inputs need not exist or be unspent. Output totals must not exceed input
    totals. Zero-valued outputs and zero fees are allowed; no relay policy is
    enforced. The return value is binary, ready for a .psbt file or Base64.
    """
    if not inputs or not outputs:
        raise EncodingError("Provide at least one input and one output")
    _uint(version, 0x7FFFFFFF, "Transaction version")
    _uint(locktime, 0xFFFFFFFF, "Locktime")
    seen = set()
    tx_inputs = []
    input_maps = []
    output_maps = []
    globals_ = []
    for item in inputs:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", item.txid):
            raise EncodingError("Transaction ID must have 64 hexadecimal digits")
        index = _uint(item.output_index, 0xFFFFFFFF, "Previous output index")
        outpoint = (item.txid.lower(), index)
        if outpoint in seen:
            raise EncodingError("Duplicate input outpoint")
        seen.add(outpoint)
        sequence = int(item.sequence) if isinstance(item.sequence, InputSequence) else item.sequence
        sequence = _uint(sequence, 0xFFFFFFFF, "Sequence")
        tx_inputs.append(bytes.fromhex(item.txid)[::-1] + index.to_bytes(4, "little")
                         + b"\x00" + sequence.to_bytes(4, "little"))
        entries = _metadata(item.spend)
        entries.extend([(b"\x01", _txout(item.amount, item.spend.script_pubkey)),
                        (b"\x03", b"\x01\x00\x00\x00")])
        input_maps.append(_map(entries))
    tx_outputs = []
    for item in outputs:
        tx_outputs.append(_txout(item.amount, item.script_pubkey))
        if item.spend is not None and item.script_pubkey != item.spend.script_pubkey:
            raise EncodingError("Output script does not match its wallet metadata")
        output_maps.append(_map(_metadata(item.spend, output=True) if item.spend else []))
    total_in = sum(item.amount for item in inputs)
    total_out = sum(item.amount for item in outputs)
    _uint(total_in, MAX_MONEY, "Total input amount")
    _uint(total_out, MAX_MONEY, "Total output amount")
    if total_out > total_in:
        raise EncodingError("Total outputs exceed the declared input amounts")
    for item in (*inputs, *outputs):
        if item.spend:
            for xpub, origin in item.spend.xpubs:
                if not isinstance(xpub, bytes) or len(xpub) != 78 or xpub[4] != len(origin.path):
                    raise EncodingError("Extended key metadata has an invalid length or origin depth")
                # Manually constructed SegwitSpend objects must obey the same
                # watch-only version and curve-point checks as imported xpubs.
                ExtendedKey.parse(base58check_encode(xpub))
                globals_.append((b"\x01" + xpub, origin.serialize()))
    tx = (version.to_bytes(4, "little") + _compact_size(len(inputs)) + b"".join(tx_inputs)
          + _compact_size(len(outputs)) + b"".join(tx_outputs) + locktime.to_bytes(4, "little"))
    globals_.append((b"\x00", tx))
    return b"psbt\xff" + _map(globals_) + b"".join(input_maps) + b"".join(output_maps)
