"""Parse legacy and SegWit Bitcoin transaction serialization."""

from __future__ import annotations

from dataclasses import dataclass
import re

from .errors import EncodingError
from .hashing import hash256

__all__ = [
    "Transaction",
    "TransactionInput",
    "TransactionOutput",
    "parse_transaction",
]


@dataclass(frozen=True)
class TransactionInput:
    """An input decoded from a serialized transaction."""

    previous_txid: str
    output_index: int
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class TransactionOutput:
    """An output amount in satoshis and its locking script."""

    amount: int
    script_pubkey: bytes


@dataclass(frozen=True)
class Transaction:
    """A decoded transaction and identifiers derived from its serialization."""

    version: int
    inputs: tuple[TransactionInput, ...]
    outputs: tuple[TransactionOutput, ...]
    locktime: int
    hex: str
    txid: str
    wtxid: str
    size: int
    weight: int
    vsize: int
    has_witness: bool


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def read(self, size: int, label: str) -> bytes:
        if size < 0 or size > self.remaining:
            raise EncodingError(f"Truncated transaction {label}")
        start = self.offset
        self.offset += size
        return self.data[start:self.offset]

    def uint(self, size: int, label: str, *, signed: bool = False) -> int:
        return int.from_bytes(self.read(size, label), "little", signed=signed)

    def compact_size(self, label: str) -> int:
        prefix = self.uint(1, label)
        if prefix < 0xFD:
            return prefix
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[prefix]
        value = self.uint(size, label)
        minimum = {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[prefix]
        if value < minimum:
            raise EncodingError(f"Noncanonical CompactSize for {label}")
        return value

    def blob(self, label: str) -> bytes:
        return self.read(self.compact_size(f"{label} length"), label)


def _bounded_count(reader: _Reader, label: str, minimum_size: int) -> int:
    count = reader.compact_size(f"{label} count")
    if count > reader.remaining // minimum_size:
        raise EncodingError(f"Transaction {label} count exceeds the remaining data")
    return count


def parse_transaction(raw_hex: str) -> Transaction:
    """Decode a complete legacy or SegWit transaction hexadecimal string.

    The parser validates canonical wire encoding, not transaction consensus or
    relay validity. Scripts and witness elements are returned as uninterpreted
    bytes, and output amounts preserve their signed 64-bit wire value.
    """
    if not isinstance(raw_hex, str):
        raise EncodingError("Transaction HEX must be a string")
    if not raw_hex or len(raw_hex) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", raw_hex):
        raise EncodingError("Transaction HEX must contain complete hexadecimal bytes")

    raw = bytes.fromhex(raw_hex)
    reader = _Reader(raw)
    version_bytes = reader.read(4, "version")
    version = int.from_bytes(version_bytes, "little")

    body_start = reader.offset
    input_count = reader.compact_size("input count")
    has_witness = False
    empty_transaction = False
    if input_count == 0:
        flag = reader.uint(1, "witness flag")
        if flag == 0:
            empty_transaction = True
        elif flag == 1:
            has_witness = True
        else:
            raise EncodingError("Unsupported transaction witness flag")
        if has_witness:
            body_start = reader.offset
            input_count = reader.compact_size("input count")
            if input_count == 0:
                raise EncodingError("Witness transaction must contain at least one input")
    if not empty_transaction and input_count > reader.remaining // 41:
        raise EncodingError("Transaction input count exceeds the remaining data")

    inputs: list[TransactionInput] = []
    for _ in range(input_count):
        previous_txid = reader.read(32, "input transaction ID")[::-1].hex()
        output_index = reader.uint(4, "input output index")
        script_sig = reader.blob("input script")
        sequence = reader.uint(4, "input sequence")
        inputs.append(TransactionInput(previous_txid, output_index, script_sig, sequence))

    output_count = 0 if empty_transaction else _bounded_count(reader, "output", 9)
    outputs: list[TransactionOutput] = []
    for _ in range(output_count):
        amount = reader.uint(8, "output amount", signed=True)
        script_pubkey = reader.blob("output script")
        outputs.append(TransactionOutput(amount, script_pubkey))
    body_end = reader.offset

    if has_witness:
        any_witness = False
        for index, item in enumerate(inputs):
            item_count = _bounded_count(reader, "witness item", 1)
            witness = tuple(reader.blob("witness item") for _ in range(item_count))
            any_witness |= bool(witness)
            inputs[index] = TransactionInput(
                item.previous_txid,
                item.output_index,
                item.script_sig,
                item.sequence,
                witness,
            )
        if not any_witness:
            raise EncodingError("Superfluous transaction witness record")

    locktime_bytes = reader.read(4, "locktime")
    locktime = int.from_bytes(locktime_bytes, "little")
    if reader.remaining:
        raise EncodingError("Transaction HEX contains trailing data")

    stripped = raw if not has_witness else version_bytes + raw[body_start:body_end] + locktime_bytes
    txid = hash256(stripped)[::-1].hex()
    wtxid = hash256(raw)[::-1].hex()
    size = len(raw)
    weight = len(stripped) * 3 + size
    return Transaction(
        version,
        tuple(inputs),
        tuple(outputs),
        locktime,
        raw_hex,
        txid,
        wtxid,
        size,
        weight,
        (weight + 3) // 4,
        has_witness,
    )
