"""Minimal Bitcoin Core JSON-RPC client over HTTP (replaces ``tinyrpc``).

``NodeRPC`` uses only the standard library. Attribute access maps to RPC
methods, so ``rpc.getblock(hash, 2)`` and ``rpc.getrawtransaction(txid, True)``
work like ``tinyrpc``'s ``get_proxy()``. Node errors raise :class:`RpcError`,
whose ``args[0]`` is the node's message (matching the old call sites that
surfaced ``error.args[0]``).
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

from .errors import ConnectionError, RpcError

__all__ = ["NodeRPC"]


class NodeRPC:
    """A JSON-RPC 2.0 client for a Bitcoin Core node."""

    def __init__(self, url: str, user: str | None = None, password: str | None = None,
                 timeout: float = 30) -> None:
        self.url = url
        self.timeout = timeout
        self._id = 0
        self._auth: str | None = None
        if user is not None:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self._auth = "Basic " + token

    # -- transport --------------------------------------------------------- #

    def _post(self, payload: bytes) -> object:
        headers = {"Content-Type": "application/json"}
        if self._auth:
            headers["Authorization"] = self._auth
        req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                return json.loads(body)
            except (ValueError, json.JSONDecodeError):
                raise RpcError(f"HTTP {exc.code} {exc.reason}") from exc
        except (urllib.error.URLError, OSError) as exc:
            raise ConnectionError(f"unable to reach node at {self.url}: {exc}") from exc
        try:
            return json.loads(body)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RpcError(f"invalid JSON-RPC response: {body[:200]!r}") from exc

    @staticmethod
    def _result(data: dict):
        error = data.get("error")
        if error:
            if isinstance(error, dict):
                raise RpcError(error.get("message", "RPC error"), error.get("code"))
            raise RpcError(str(error))
        if "result" not in data:
            raise RpcError(f"JSON-RPC response has no result: {data!r}")
        return data["result"]

    # -- public API -------------------------------------------------------- #

    def call(self, method: str, *params):
        """Invoke ``method`` with positional ``params`` and return the result."""
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": list(params)}
        ).encode()
        data = self._post(payload)
        if not isinstance(data, dict):
            raise RpcError(f"unexpected response shape: {type(data).__name__}")
        if data.get("id") != self._id:
            raise RpcError(f"mismatched JSON-RPC response id: {data.get('id')!r}")
        return self._result(data)

    def batch(self, calls: list[tuple]) -> list:
        """Run several ``(method, *params)`` tuples in one request, in order."""
        if not calls:
            return []
        reqs = []
        for i, call in enumerate(calls):
            method, params = call[0], list(call[1:])
            reqs.append({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
        data = self._post(json.dumps(reqs).encode())
        if not isinstance(data, list):
            raise RpcError("expected a batch (list) response")
        if any(not isinstance(item, dict) or "id" not in item for item in data):
            raise RpcError("malformed JSON-RPC batch response")
        by_id = {item["id"]: item for item in data}
        if len(data) != len(calls) or set(by_id) != set(range(len(calls))):
            raise RpcError("mismatched JSON-RPC batch response ids")
        return [self._result(by_id[i]) for i in range(len(calls))]

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        def method(*params):
            return self.call(name, *params)

        return method
