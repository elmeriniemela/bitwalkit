"""NodeRPC over a real in-process HTTP transport."""

import base64
import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from collections.abc import Callable, Generator
from typing import Any, ClassVar

import pytest

from bitwalkit import NodeRPC, RpcError


class Handler(BaseHTTPRequestHandler):
    response_status: ClassVar[int] = 200
    response: ClassVar[Callable[[dict[str, object]], object]]
    rpc_request: ClassVar[dict[str, object]] = {}
    authorization: ClassVar[str | None] = None

    def do_POST(self) -> None:
        type(self).rpc_request = json.loads(
            self.rfile.read(int(self.headers["Content-Length"]))
        )
        type(self).authorization = self.headers.get("Authorization")
        body = type(self).response(type(self).rpc_request)
        self.send_response(type(self).response_status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else json.dumps(body).encode())

    def log_message(self, format: str, *args: Any) -> None:
        pass


@contextlib.contextmanager
def rpc_server(
    status: int,
    response: Callable[[dict[str, object]], object],
) -> Generator[NodeRPC, None, None]:
    Handler.response_status = status
    Handler.response = response
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield NodeRPC(f"http://127.0.0.1:{server.server_port}", "alice", "secret")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_http_transport_posts_json_and_basic_auth():
    with rpc_server(200, lambda request: {
        "id": request["id"], "result": 42, "error": None,
    }) as rpc:
        assert rpc.getblockcount() == 42
    assert Handler.rpc_request["method"] == "getblockcount"
    token = base64.b64encode(b"alice:secret").decode()
    assert Handler.authorization == f"Basic {token}"


def test_http_error_body_preserves_core_rpc_error():
    with rpc_server(500, lambda request: {
        "id": request["id"],
        "result": None,
        "error": {"code": -5, "message": "Block not found"},
    }) as rpc:
        with pytest.raises(RpcError) as error:
            rpc.getblock("missing")
    assert error.value.code == -5
    assert str(error.value) == "Block not found"


def test_invalid_http_json_is_rejected():
    with rpc_server(200, lambda request: b"not-json") as rpc:
        with pytest.raises(RpcError):
            rpc.getblockcount()
