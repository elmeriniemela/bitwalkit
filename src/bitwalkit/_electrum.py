"""Internal ElectrumX client: newline-delimited JSON-RPC 2.0 over TCP/SSL.

This is a private module -- callers use :class:`bitwalkit.chain.ChainQuery`,
which speaks in addresses and hides scripthashes and Electrum method names.
The client supports TCP or TLS connections, configurable timeouts, and batch
requests.
"""

from __future__ import annotations

import json
import socket
import ssl

from .errors import ConnectionError, RpcError

__all__ = ["ElectrumClient"]


class ElectrumClient:
    """A short-lived connection to an ElectrumX server."""

    def __init__(self, host: str, port: int, use_ssl: bool = False, timeout: float = 10) -> None:
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""

    # -- connection -------------------------------------------------------- #

    def connect(self) -> "ElectrumClient":
        if self._sock is not None:
            return self
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if self.use_ssl:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            sock.settimeout(self.timeout)
        except (OSError, ssl.SSLError) as exc:
            raise ConnectionError(
                f"unable to connect to Electrum server {self.host}:{self.port}: {exc}"
            ) from exc
        self._sock = sock
        return self

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
                self._buf = b""

    def __enter__(self) -> "ElectrumClient":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    # -- transport --------------------------------------------------------- #

    def _send(self, obj) -> None:
        if self._sock is None:
            self.connect()
        assert self._sock is not None
        try:
            self._sock.sendall(json.dumps(obj).encode() + b"\n")
        except OSError as exc:
            raise ConnectionError(f"Electrum send failed: {exc}") from exc

    def _recv_line(self) -> bytes:
        assert self._sock is not None
        while b"\n" not in self._buf:
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout as exc:
                raise ConnectionError("Electrum server timed out") from exc
            except OSError as exc:
                raise ConnectionError(f"Electrum recv failed: {exc}") from exc
            if not chunk:
                raise ConnectionError("Electrum server closed the connection")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line

    @staticmethod
    def _result(item: dict):
        if not isinstance(item, dict):
            raise RpcError(f"invalid Electrum response: {item!r}")
        error = item.get("error")
        if error:
            if isinstance(error, dict):
                raise RpcError(error.get("message", "Electrum error"), error.get("code"))
            raise RpcError(str(error))
        if "result" not in item:
            raise RpcError(f"Electrum response has no result: {item!r}")
        return item["result"]

    def _receive(self):
        try:
            return json.loads(self._recv_line())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RpcError("invalid JSON from Electrum server") from exc

    # -- public calls ------------------------------------------------------ #

    def call(self, method: str, params: list):
        self._send({"jsonrpc": "2.0", "id": 0, "method": method, "params": params})
        data = self._receive()
        if not isinstance(data, dict) or data.get("id") != 0:
            raise RpcError(f"mismatched Electrum response: {data!r}")
        return self._result(data)

    def batch(self, method: str, params_list: list[list]) -> list:
        """Call ``method`` once per entry in ``params_list``; results stay in order."""
        if not params_list:
            return []
        reqs = [
            {"jsonrpc": "2.0", "id": i, "method": method, "params": params}
            for i, params in enumerate(params_list)
        ]
        self._send(reqs)
        data = self._receive()
        if not isinstance(data, list) or len(data) != len(params_list):
            raise RpcError("malformed Electrum batch response")
        if any(not isinstance(item, dict) or "id" not in item for item in data):
            raise RpcError("malformed Electrum batch response")
        by_id = {item["id"]: item for item in data}
        if set(by_id) != set(range(len(params_list))):
            raise RpcError("mismatched Electrum batch response ids")
        return [self._result(by_id[i]) for i in range(len(params_list))]
