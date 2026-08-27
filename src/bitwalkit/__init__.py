"""bitwalkit -- Bitcoin Wallet Toolkit.

Three dependency-free capabilities:

* :class:`NodeRPC` -- call a Bitcoin Core node over JSON-RPC.
* :class:`Account` / :class:`MultisigAccount` -- watch-only HD address
  derivation from master/account extended public keys (xpub/ypub/zpub/...).
* :class:`ChainQuery` -- fetch an address's balance / UTXOs / history (backed
  by an Electrum server, but the caller only ever deals in addresses).
"""

from __future__ import annotations

from .address import (
    address_from_pubkey,
    address_from_script,
    address_to_script,
    address_to_scripthash,
    p2ms_script,
    script_to_scripthash,
)
from .bip32 import ExtendedKey
from .chain import Balance, ChainQuery, HistoryEntry, Utxo
from .descriptor import descriptor_checksum
from .encoding import (
    base58check_decode,
    base58check_encode,
    bech32_decode,
    bech32_encode,
)
from .errors import (
    BitwalkitError,
    ConnectionError,
    DerivationError,
    EncodingError,
    RpcError,
)
from .hd import Account, MultisigAccount
from .rpc import NodeRPC

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # rpc
    "NodeRPC",
    # derivation
    "ExtendedKey",
    "Account",
    "MultisigAccount",
    "descriptor_checksum",
    # balances
    "ChainQuery",
    "Balance",
    "Utxo",
    "HistoryEntry",
    # address / encoding helpers
    "address_from_pubkey",
    "address_from_script",
    "address_to_script",
    "address_to_scripthash",
    "script_to_scripthash",
    "p2ms_script",
    "base58check_encode",
    "base58check_decode",
    "bech32_encode",
    "bech32_decode",
    # errors
    "BitwalkitError",
    "RpcError",
    "ConnectionError",
    "DerivationError",
    "EncodingError",
]
