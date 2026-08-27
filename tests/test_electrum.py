"""Electrum JSON-RPC response validation vectors."""

import json

import pytest

from bitwalkit._electrum import ElectrumClient
from bitwalkit.errors import RpcError


class FakeElectrum(ElectrumClient):
    def __init__(self, reply):
        super().__init__("electrum.invalid", 50001)
        self.reply = reply
        self.sent = []

    def _send(self, obj):
        self.sent.append(obj)

    def _recv_line(self):
        if isinstance(self.reply, bytes):
            return self.reply
        return json.dumps(self.reply).encode()


def test_call_validates_id_and_returns_result():
    client = FakeElectrum({"jsonrpc": "2.0", "id": 0, "result": "status"})
    assert client.call("blockchain.scripthash.subscribe", ["ab"]) == "status"
    assert client.sent[0]["params"] == ["ab"]


def test_batch_restores_request_order():
    client = FakeElectrum([
        {"id": 1, "result": "second"},
        {"id": 0, "result": "first"},
    ])
    assert client.batch("method", [[1], [2]]) == ["first", "second"]


@pytest.mark.parametrize("reply", [
    b"not-json",
    [],
    {"id": 4, "result": None},
    {"id": 0},
    {"id": 0, "error": {"code": -1, "message": "failure"}},
])
def test_call_rejects_invalid_or_error_replies(reply):
    with pytest.raises(RpcError):
        FakeElectrum(reply).call("method", [])


@pytest.mark.parametrize("reply", [
    {"id": 0, "result": 1},
    [{"id": 0, "result": 1}],
    [{"id": 0, "result": 1}, {"id": 0, "result": 2}],
    [{"result": 1}, {"id": 1, "result": 2}],
])
def test_batch_rejects_invalid_counts_and_ids(reply):
    with pytest.raises(RpcError):
        FakeElectrum(reply).batch("method", [[1], [2]])
