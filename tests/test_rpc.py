"""NodeRPC behaviour with a stubbed transport (no real node needed)."""

import json

import pytest

from bitwalkit.errors import ConnectionError, RpcError
from bitwalkit.rpc import NodeRPC


class FakeRPC(NodeRPC):
    """NodeRPC whose HTTP layer is replaced by a canned responder."""

    def __init__(self, responder):
        super().__init__("http://node.invalid:8332", "user", "pw")
        self._responder = responder
        self.sent = []

    def _post(self, payload):
        req = json.loads(payload)
        self.sent.append(req)
        return self._responder(req)


def test_call_and_attribute_proxy():
    rpc = FakeRPC(lambda req: {"id": req["id"], "result": {"height": 42}, "error": None})
    assert rpc.call("getblock", "hash", 2)["height"] == 42
    # Attribute access maps directly to a method call.
    assert rpc.getblock("hash", 2)["height"] == 42
    assert rpc.sent[-1]["method"] == "getblock"
    assert rpc.sent[-1]["params"] == ["hash", 2]


def test_rpc_error_message_in_args0():
    rpc = FakeRPC(lambda req: {"id": req["id"], "result": None,
                               "error": {"code": -8, "message": "Block not found"}})
    with pytest.raises(RpcError) as ei:
        rpc.getblock("bad")
    assert ei.value.args[0] == "Block not found"
    assert ei.value.code == -8


def test_batch_preserves_order():
    def responder(reqs):
        # Reply out of order to prove we re-map by id.
        return [{"id": r["id"], "result": r["id"] * 10, "error": None}
                for r in reversed(reqs)]

    rpc = FakeRPC(responder)
    assert rpc.batch([("a",), ("b",), ("c",)]) == [0, 10, 20]


def test_empty_batch_does_not_post():
    rpc = FakeRPC(lambda req: None)
    assert rpc.batch([]) == []
    assert rpc.sent == []


@pytest.mark.parametrize("response", [
    {"id": 99, "result": True},
    {"id": 1, "error": None},
    [],
])
def test_call_rejects_malformed_responses(response):
    rpc = FakeRPC(lambda req: response)
    with pytest.raises(RpcError):
        rpc.call("bad")


@pytest.mark.parametrize("response", [
    [{"id": 0, "result": 1}],
    [{"id": 0, "result": 1}, {"id": 0, "result": 2}],
    [{"result": 1}, {"id": 1, "result": 2}],
])
def test_batch_rejects_missing_duplicate_or_unidentified_replies(response):
    rpc = FakeRPC(lambda req: response)
    with pytest.raises(RpcError):
        rpc.batch([("a",), ("b",)])


def test_auth_header_is_set():
    rpc = NodeRPC("http://x", "alice", "secret")
    assert rpc._auth is not None and rpc._auth.startswith("Basic ")


def test_connection_error_is_wrapped():
    rpc = NodeRPC("http://127.0.0.1:1", "u", "p", timeout=0.2)
    with pytest.raises(ConnectionError):
        rpc.getblockcount()
