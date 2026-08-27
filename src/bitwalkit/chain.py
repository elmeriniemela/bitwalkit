"""Address-oriented balance / UTXO queries.

``ChainQuery`` is the public, Electrum-agnostic surface: callers pass an
address (or a list of them) and get back a balance, UTXOs, or history. The
address -> scripthash conversion and the ElectrumX protocol details are hidden.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._electrum import ElectrumClient
from .address import address_to_scripthash
from .errors import RpcError

__all__ = ["ChainQuery", "Balance", "Utxo", "HistoryEntry"]


@dataclass(frozen=True)
class Balance:
    """Confirmed and unconfirmed balance, in satoshis."""

    confirmed: int
    unconfirmed: int

    @property
    def total(self) -> int:
        return self.confirmed + self.unconfirmed


@dataclass(frozen=True)
class Utxo:
    """An unspent output paying to a queried address."""

    txid: str
    vout: int
    value: int  # satoshis
    height: int  # 0 = unconfirmed (mempool)


@dataclass(frozen=True)
class HistoryEntry:
    """A transaction touching a queried address."""

    txid: str
    height: int


class ChainQuery:
    """Query balances / UTXOs / history for addresses via an Electrum server."""

    def __init__(self, host: str = "127.0.0.1", port: int | None = None,
                 use_ssl: bool = False, network: str = "mainnet", timeout: float = 10) -> None:
        self.host = host
        self.port = port if port is not None else (50002 if use_ssl else 50001)
        self.use_ssl = use_ssl
        self.network = network
        self.timeout = timeout

    def _client(self) -> ElectrumClient:
        return ElectrumClient(self.host, self.port, self.use_ssl, self.timeout)

    # -- single-address helpers ------------------------------------------- #

    def get_balance(self, address: str) -> Balance:
        sh = address_to_scripthash(address, self.network)
        with self._client() as c:
            res = c.call("blockchain.scripthash.get_balance", [sh])
        return _to_balance(res)

    def get_utxos(self, address: str) -> list[Utxo]:
        sh = address_to_scripthash(address, self.network)
        with self._client() as c:
            res = c.call("blockchain.scripthash.listunspent", [sh])
        return _to_utxos(res)

    def get_history(self, address: str) -> list[HistoryEntry]:
        sh = address_to_scripthash(address, self.network)
        with self._client() as c:
            res = c.call("blockchain.scripthash.get_history", [sh])
        return _to_history(res)

    def get_status(self, address: str) -> str | None:
        """Return the Electrum history status used for change detection."""
        sh = address_to_scripthash(address, self.network)
        with self._client() as c:
            res = c.call("blockchain.scripthash.subscribe", [sh])
        return _to_status(res)

    # -- batched (one round-trip for many addresses) ---------------------- #

    def get_balances(self, addresses: list[str]) -> dict[str, Balance]:
        if not addresses:
            return {}
        shs = [address_to_scripthash(a, self.network) for a in addresses]
        with self._client() as c:
            results = c.batch("blockchain.scripthash.get_balance", [[sh] for sh in shs])
        return {addr: _to_balance(r) for addr, r in zip(addresses, results)}

    def get_utxos_many(self, addresses: list[str]) -> dict[str, list[Utxo]]:
        if not addresses:
            return {}
        shs = [address_to_scripthash(a, self.network) for a in addresses]
        with self._client() as c:
            results = c.batch("blockchain.scripthash.listunspent", [[sh] for sh in shs])
        return {addr: _to_utxos(r) for addr, r in zip(addresses, results)}

    def get_history_many(self, addresses: list[str]) -> dict[str, list[HistoryEntry]]:
        if not addresses:
            return {}
        shs = [address_to_scripthash(a, self.network) for a in addresses]
        with self._client() as c:
            results = c.batch("blockchain.scripthash.get_history", [[sh] for sh in shs])
        return {addr: _to_history(r) for addr, r in zip(addresses, results)}

    def get_statuses(self, addresses: list[str]) -> dict[str, str | None]:
        """Return subscription statuses for several addresses in one request."""
        if not addresses:
            return {}
        shs = [address_to_scripthash(a, self.network) for a in addresses]
        with self._client() as c:
            results = c.batch("blockchain.scripthash.subscribe", [[sh] for sh in shs])
        return {addr: _to_status(r) for addr, r in zip(addresses, results)}


def _to_balance(res) -> Balance:
    if not isinstance(res, dict) or "confirmed" not in res or "unconfirmed" not in res:
        raise RpcError(f"invalid balance response: {res!r}")
    return Balance(int(res["confirmed"]), int(res["unconfirmed"]))


def _to_utxos(res) -> list[Utxo]:
    if not isinstance(res, list):
        raise RpcError(f"invalid UTXO response: {res!r}")
    return [
        Utxo(u["tx_hash"], int(u["tx_pos"]), int(u["value"]), int(u["height"]))
        for u in res
    ]


def _to_history(res) -> list[HistoryEntry]:
    if not isinstance(res, list):
        raise RpcError(f"invalid history response: {res!r}")
    return [HistoryEntry(h["tx_hash"], int(h["height"])) for h in res]


def _to_status(res) -> str | None:
    if res is not None and not isinstance(res, str):
        raise RpcError(f"invalid subscription status: {res!r}")
    return res
