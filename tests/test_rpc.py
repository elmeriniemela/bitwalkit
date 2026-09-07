"""NodeRPC behaviour with a stubbed transport (no real node needed)."""

import json
from pathlib import Path

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
    {"id": True, "result": True},
    {"id": 1.0, "result": True},
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
    [{"id": 0, "result": 1}, {"id": True, "result": 2}],
    [{"id": 0, "result": 1}, {"id": 1.0, "result": 2}],
    [{"id": 0, "result": 1}, {"id": [], "result": 2}],
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


def test_from_config_parses_core_conf(tmp_path):
    conf_file = tmp_path / "bitcoin.conf"
    conf_file.write_text(
        "# Bitcoin Core config\n"
        "[main]\n"
        "rpcuser=testuser\n"
        "rpcpassword=\"secret123\"\n"
        "rpcconnect=127.0.0.1\n"
        "rpcport=18335\n"
        "rpcwallet=wallet1\n"
    )
    rpc = NodeRPC.from_config(conf_file)
    assert rpc.url == "http://127.0.0.1:18335/wallet/wallet1"
    assert rpc._auth is not None


def test_from_config_defaults_and_networks(tmp_path):
    f_main = tmp_path / "main.conf"
    f_main.write_text("rpcuser=u\nrpcpassword=p\n")
    assert NodeRPC.from_config(f_main).url == "http://127.0.0.1:8332"

    f_test = tmp_path / "test.conf"
    f_test.write_text("rpcuser=u\ntestnet=1\n")
    assert NodeRPC.from_config(f_test).url == "http://127.0.0.1:18332"

    f_reg = tmp_path / "reg.conf"
    f_reg.write_text("rpcuser=u\nchain=regtest\n")
    assert NodeRPC.from_config(f_reg).url == "http://127.0.0.1:18443"

    f_sig = tmp_path / "sig.conf"
    f_sig.write_text("rpcuser=u\nsignet=1\n")
    assert NodeRPC.from_config(f_sig).url == "http://127.0.0.1:38332"


def test_from_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        NodeRPC.from_config(Path("/nonexistent/bitcoin.conf"))



@pytest.mark.parametrize('http_error', [False, True])
@pytest.mark.parametrize('failure', ['truncated', 'timeout'])
def test_response_read_failure_is_connection_error_and_closes_body(monkeypatch, http_error, failure):
    import http.client
    import io
    import urllib.error
    import urllib.request
    from email.message import Message

    class BrokenBody(io.BytesIO):
        def read(self, *args):
            if failure == 'truncated':
                raise http.client.IncompleteRead(b'{', 100)
            raise TimeoutError('read timed out')

    body = BrokenBody()
    def open_request(*args, **kwargs):
        if http_error:
            raise urllib.error.HTTPError('http://unused.invalid', 500, 'Server error', Message(), body)
        return body

    monkeypatch.setattr(urllib.request, 'urlopen', open_request)
    with pytest.raises(ConnectionError) as exc:
        NodeRPC('http://unused.invalid').sendrawtransaction('hex')
    assert isinstance(exc.value.__cause__, (http.client.IncompleteRead, TimeoutError))
    assert body.closed
