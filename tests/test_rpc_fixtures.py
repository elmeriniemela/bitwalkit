"""NodeRPC behavior against representative Bitcoin Core response fixtures."""

import json

import pytest

from bitwalkit.errors import RpcError
from bitwalkit.rpc import NodeRPC

# A serialized mainnet transaction used as an opaque RPC result fixture.
_RAWTX_HEX = (
    "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da"
    "95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab"
    "47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3"
    "d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3"
    "d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a24"
    "8e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c"
    "019e756c88ac6acb0700"
)

_RAWTX = {
    "in_active_chain": True,
    "txid": "tx-search",
    "hex": _RAWTX_HEX,
    "hash": "hash-tx-search",
    "version": 2,
    "size": 200,
    "vsize": 140,
    "weight": 560,
    "locktime": 0,
    "vin": [{"sequence": 1, "txid": "prev-tx-search", "vout": 0}],
    "vout": [{"n": 0, "value": 1.23, "scriptPubKey": {
        "hex": "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
        "asm": "OP_DUP OP_HASH160", "type": "pubkeyhash"}}],
}

_BLOCK = {
    "confirmations": 1, "height": 10, "version": 4,
    "merkleroot": "merkle-block-auto", "time": 1700000000, "mediantime": 1700000000,
    "nonce": 123, "bits": "1d00ffff", "difficulty": 1.0, "chainwork": "cw-block-auto",
    "nTx": 1, "previousblockhash": "block-prev", "size": 1000, "strippedsize": 900,
    "weight": 3900, "tx": [_RAWTX],
}


class FakeRPC(NodeRPC):
    def __init__(self, responder):
        super().__init__("http://node.invalid:8332", "user", "pw")
        self._responder = responder
        self.sent = []

    def _post(self, payload):
        req = json.loads(payload)
        self.sent.append(req)
        return self._responder(req)


def _ok(result):
    return lambda req: {"id": req["id"], "result": result, "error": None}


def test_getrawtransaction_verbose_result_passthrough():
    rpc = FakeRPC(_ok(_RAWTX))
    res = rpc.getrawtransaction("tx-search", True)
    assert res == _RAWTX
    assert res["vout"][0]["scriptPubKey"]["hex"].startswith("76a914")
    # Params are forwarded exactly (txid, verbose=True).
    assert rpc.sent[-1] == {"jsonrpc": "2.0", "id": 1,
                            "method": "getrawtransaction", "params": ["tx-search", True]}


def test_getblock_verbosity_two_returns_full_txs():
    rpc = FakeRPC(_ok(_BLOCK))
    block = rpc.getblock("block-auto", 2)
    assert block["height"] == 10 and block["nTx"] == 1
    assert isinstance(block["tx"][0], dict) and block["tx"][0]["txid"] == "tx-search"


def test_getblock_verbosity_one_returns_txid_list():
    v1 = dict(_BLOCK, tx=[t["txid"] for t in _BLOCK["tx"]])
    rpc = FakeRPC(_ok(v1))
    block = rpc.getblock("block-auto", 1)
    assert block["tx"] == ["tx-search"]


@pytest.mark.parametrize("code,message", [
    (-1, "boom getblock"),
    (-2, "boom getrawtransaction"),
    (-100, "rpc failed"),
    (-8, "Block not found"),
])
def test_core_error_surfaces_message_and_code(code, message):
    rpc = FakeRPC(lambda req: {"id": req["id"], "result": None,
                               "error": {"code": code, "message": message}})
    with pytest.raises(RpcError) as ei:
        rpc.getblock("x")
    assert ei.value.args[0] == message
    assert ei.value.code == code
