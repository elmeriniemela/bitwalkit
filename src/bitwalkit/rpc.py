"""Minimal, standard-library Bitcoin Core JSON-RPC client over HTTP.

Attribute access maps to RPC methods, so ``rpc.getblock(hash, 2)`` and
``rpc.getrawtransaction(txid, True)`` work like direct node calls. Node errors
raise :class:`RpcError` and retain the node's numeric error code.
"""

from __future__ import annotations

import base64
import http.client
import json
from pathlib import Path
import threading
import urllib.error
import urllib.request

from .errors import ConnectionError, RpcError

__all__ = ["NodeRPC"]


class NodeRPC:
    """Call a Bitcoin Core-compatible JSON-RPC endpoint over HTTP.

    Construct a client with an endpoint and optional basic-auth credentials,
    or use ``NodeRPC.from_config(Path("bitcoin.conf"))`` for a local configuration
    file. Public attribute access creates RPC callables, so
    ``node.getblock(block_hash, 1)`` is equivalent to
    ``node.call("getblock", block_hash, 1)``. Node-specific return values are
    passed through as decoded JSON; node errors raise RpcError with their code.

    Construction performs no network access. Calls and batches may share a
    client concurrently while its URL, timeout, and credentials remain
    unchanged. Request-ID allocation is protected by a short lock, while HTTP
    I/O remains concurrent. Each response is checked against the identifiers
    for its own request, including strict integer-ID checks.

    The client provides transport and response handling, not application-level
    retries or Bitcoin policy validation. In particular, a connection failure
    after sending a mutating RPC does not establish whether the node applied it.
    """

    def __init__(self, url: str, user: str | None = None, password: str | None = None,
                 timeout: float = 30) -> None:
        """Configure a reusable RPC client without opening a connection.

        ``url`` is the complete HTTP endpoint, optionally including a wallet path.
        When ``user`` is supplied, HTTP Basic authentication is configured using
        ``password`` or an empty password; with ``user=None``, no Authorization
        header is added. ``timeout`` is passed to urllib in seconds for each HTTP
        request and defaults to 30.

        The constructor also initializes the counter and lock used by single-call
        request IDs. Create separate instances when callers need different timeouts
        or endpoints. When sharing an instance between threads, finish configuring
        it before issuing calls and do not modify its attributes during use.
        """
        self.url = url
        self.timeout = timeout
        self._id = 0
        self._id_lock = threading.Lock()
        self._auth: str | None = None
        if user is not None:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self._auth = "Basic " + token

    # -- transport --------------------------------------------------------- #

    def _post(self, payload: bytes) -> object:
        """Send serialized JSON bytes and decode the HTTP response body.

        ``payload`` is an already encoded single request or batch prepared by
        ``call()`` or ``batch()``. POST it to the configured URL with a JSON content
        type and optional Basic authentication, then return the JSON-decoded body
        without interpreting result fields or validating request IDs.

        HTTP error responses are also decoded as JSON so Bitcoin RPC error details
        remain available to higher layers. Raise RpcError for invalid JSON or a
        non-JSON HTTP error response. Wrap connection, timeout, and HTTP read errors,
        including truncated responses, in ConnectionError and preserve their cause.
        Opened response bodies are closed on both success and error paths.

        This transport hook does not retry: callers must account for a mutating
        request that might have reached the node before a response was lost. Tests
        can override it to supply deterministic responses without network access.
        """
        headers = {"Content-Type": "application/json"}
        if self._auth:
            headers["Authorization"] = self._auth
        req = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            try:
                response = urllib.request.urlopen(req, timeout=self.timeout)
            except urllib.error.HTTPError as exc:
                with exc:
                    body = exc.read()
                try:
                    return json.loads(body)
                except ValueError:
                    raise RpcError(f"HTTP {exc.code} {exc.reason}") from exc
            else:
                with response:
                    body = response.read()
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            raise ConnectionError(f"unable to reach node at {self.url}: {exc}") from exc
        try:
            return json.loads(body)
        except (ValueError, json.JSONDecodeError) as exc:
            raise RpcError(f"invalid JSON-RPC response: {body[:200]!r}") from exc

    @staticmethod
    def _result(data: dict):
        """Extract a result or raise the node's error from a response object.

        ``data`` is a decoded response dictionary whose outer shape and request ID
        have already been checked by the caller. A truthy ``error`` takes precedence
        over ``result``. Dictionary errors supply the RpcError message and numeric
        code; other error values are converted to a message string.

        Return the ``result`` value unchanged, including None or False when those
        are legitimate results. Raise RpcError when there is no result field and no
        reported error. This stateless helper performs no network access and is
        shared by single-call and batch response handling.
        """
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
        """Invoke a named RPC with positional parameters and return its result.

        For example, ``node.call("getblock", block_hash, 1)`` sends a JSON-RPC 2.0
        request whose parameter array contains the hash and verbosity. ``params``
        must be JSON-serializable; this method does not interpret Bitcoin-specific
        arguments or support keyword-style RPC parameters.

        Each invocation copies the next request ID into its own local
        ``request_id`` variable. The lock protects only that allocation; it is
        released before the HTTP request begins, allowing other calls on this
        client to run concurrently. The response ID must be an integer equal to
        that saved value, so a later call cannot change what this call expects.

        Return the decoded result unchanged. Transport failures raise
        ConnectionError; malformed responses, mismatched IDs, and node-reported
        errors raise RpcError. There is no automatic retry, and the call may have
        changed node state even when its response cannot be obtained.
        """
        with self._id_lock:
            self._id += 1
            request_id = self._id
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": list(params)}
        ).encode()
        data = self._post(payload)
        if not isinstance(data, dict):
            raise RpcError(f"unexpected response shape: {type(data).__name__}")
        response_id = data.get("id")
        if type(response_id) is not int or response_id != request_id:
            raise RpcError(
                f"mismatched JSON-RPC response id: expected {request_id!r}, "
                f"received {response_id!r}"
            )
        return self._result(data)

    def batch(self, calls: list[tuple]) -> list:
        """Send multiple RPC calls in one HTTP request and order their results.

        ``calls`` is a list of non-empty tuples shaped as ``(method, *params)``.
        For example, ``node.batch([("getblockcount",), ("getbestblockhash",)])``
        returns two results in that same input order, even if the server returns
        its responses in a different order. An empty list returns [] without
        performing network I/O.

        IDs are local integer positions within this batch, independent of the
        single-call counter. Responses must identify every position exactly once;
        malformed, missing, duplicated, or unexpected IDs raise RpcError. A node
        error in any response also raises RpcError instead of returning partial
        results. Transport failures raise ConnectionError.

        A batch is not a transaction and does not guarantee server execution order
        or rollback. Some calls may have succeeded when another fails. Multiple
        batches and individual calls can run concurrently on the same configured
        client without sharing their response-matching state.
        """
        if not calls:
            return []
        reqs = []
        for i, call in enumerate(calls):
            method, params = call[0], list(call[1:])
            reqs.append({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
        data = self._post(json.dumps(reqs).encode())
        if not isinstance(data, list):
            raise RpcError("expected a batch (list) response")
        if any(
            not isinstance(item, dict) or type(item.get("id")) is not int
            for item in data
        ):
            raise RpcError("malformed JSON-RPC batch response")
        by_id = {item["id"]: item for item in data}
        if len(data) != len(calls) or set(by_id) != set(range(len(calls))):
            raise RpcError("mismatched JSON-RPC batch response ids")
        return [self._result(by_id[i]) for i in range(len(calls))]

    @classmethod
    def from_config(
        cls,
        path: Path,
        *,
        timeout: float = 30,
        wallet: str | None = None,
    ) -> NodeRPC:
        """Build a client from a simple Bitcoin Core or Knots configuration file.

        ``path`` names the file to read. The parser extracts ``rpcuser``,
        ``rpcpassword``, ``rpcconnect``, and ``rpcport``; the host defaults to
        127.0.0.1. Without an explicit port, the implemented network-flag checks
        select 8332 for mainnet, 18332 for testnet, 38332 for signet, or 18443 for
        regtest. ``timeout`` is forwarded to the constructor in seconds.

        A non-empty ``wallet`` argument takes precedence over ``rpcwallet`` from
        the file and appends a wallet path to the endpoint. For example,
        ``NodeRPC.from_config(Path("bitcoin.conf"), timeout=5, wallet="watch")`` prepares
        a wallet client without contacting the node.

        This is a small key/value reader, not the node's full configuration resolver.
        Blank lines, whole-line comments, and section headers are skipped; repeated
        keys use their last value regardless of section. It strips matching quotes
        around values but does not resolve includeconf files or cookie credentials.
        Use an explicit connection configuration when those node features are used.

        Return a new instance of ``cls``. FileNotFoundError identifies a missing
        configuration file; file read errors and invalid numeric ports propagate.
        RPC connectivity and authentication are checked only on a subsequent call.
        """
        if not path.is_file():
            raise FileNotFoundError(f"Bitcoin configuration file not found: {path}")

        conf: dict[str, str] = {}
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith(";"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip()
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    conf[key] = val

        user = conf.get("rpcuser")
        password = conf.get("rpcpassword")
        host = conf.get("rpcconnect", "127.0.0.1")

        if "rpcport" in conf:
            port = int(conf["rpcport"])
        else:
            testnet = conf.get("testnet") in ("1", "true") or conf.get("chain") in ("test", "testnet3", "testnet4")
            signet = conf.get("signet") in ("1", "true") or conf.get("chain") == "signet"
            regtest = conf.get("regtest") in ("1", "true") or conf.get("chain") == "regtest"
            if regtest:
                port = 18443
            elif testnet:
                port = 18332
            elif signet:
                port = 38332
            else:
                port = 8332

        wallet_name = wallet or conf.get("rpcwallet")
        if wallet_name:
            url = f"http://{host}:{port}/wallet/{wallet_name}"
        else:
            url = f"http://{host}:{port}"

        return cls(url, user=user, password=password, timeout=timeout)

    def __getattr__(self, name: str):
        """Create an RPC callable for an otherwise undefined public attribute.

        Accessing ``node.getblockcount`` returns a function which delegates its
        positional arguments to ``call("getblockcount", ...)``. Looking up the
        attribute itself performs no network access and does not verify that the
        node implements the method; those checks happen when the function is called.

        Names starting with an underscore raise AttributeError so missing private
        attributes are not accidentally treated as RPC methods. Normal Python
        attribute lookup still takes precedence for existing attributes such as
        ``url`` or ``batch``; use ``call()`` explicitly for an RPC name that collides
        with the client's own API.
        """
        if name.startswith("_"):
            raise AttributeError(name)

        def method(*params):
            """Invoke the RPC name captured by the surrounding attribute lookup.

            Pass the node method's arguments positionally, just as with ``call()``.
            The returned value and exceptions are those of ``self.call(name, *params)``;
            this wrapper adds no validation, retry, or mutable request state. It is
            created for attribute-style usage such as ``node.getblock(hash, 1)``.
            """
            return self.call(name, *params)

        return method
