"""bitwalkit -- Bitcoin Wallet Toolkit.

Dependency-free capabilities:

* :class:`NodeRPC` -- call a Bitcoin Core node over JSON-RPC.
* :class:`Account` / :class:`MultisigAccount` -- watch-only HD address
  derivation from master/account extended public keys (xpub/ypub/zpub/...).
* :class:`ChainQuery` -- fetch an address's balance / UTXOs / history (backed
  by an Electrum server, but the caller only ever deals in addresses).
* :func:`create_psbt` -- build an unsigned native SegWit PSBT from manually
  declared outpoints and amounts, without querying chain state.
"""

from __future__ import annotations

from .address import (
    address_from_pubkey,
    address_from_script,
    address_to_script,
    address_to_scripthash,
    op_return_script,
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
from .psbt import InputSequence, KeyOrigin, PSBTInput, PSBTOutput, SegwitSpend, create_psbt, derive_native_segwit, dust_threshold

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "InputSequence",
    "KeyOrigin",
    "PSBTInput",
    "PSBTOutput",
    "SegwitSpend",
    "create_psbt",
    "derive_native_segwit",
    "dust_threshold",
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
    "op_return_script",
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
