"""Exception hierarchy for bitwalkit."""

from __future__ import annotations

__all__ = [
    "BitwalkitError",
    "RpcError",
    "ConnectionError",
    "DerivationError",
    "EncodingError",
]


class BitwalkitError(Exception):
    """Base class for all bitwalkit errors."""


class EncodingError(BitwalkitError):
    """Malformed address, extended key, or other encoded data."""


class DerivationError(BitwalkitError):
    """Invalid BIP32 derivation (e.g. hardened step from a public key)."""


class ConnectionError(BitwalkitError):
    """Failure talking to a node or Electrum server (connect / timeout / IO)."""


class RpcError(BitwalkitError):
    """A Bitcoin Core JSON-RPC call returned an error.

    ``args[0]`` is the node's human-readable error message, and ``code`` is the
    JSON-RPC error code when present.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code
