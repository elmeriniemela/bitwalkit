"""ChainQuery against an in-process fake ElectrumX server (newline JSON)."""

import json
import socketserver
import threading

import pytest

from bitwalkit.chain import Balance, ChainQuery, HistoryEntry, Utxo

# Canned responses keyed by Electrum method.
_RESPONSES = {
    "blockchain.scripthash.get_balance": {"confirmed": 150000, "unconfirmed": 2500},
    "blockchain.scripthash.listunspent": [
        {"tx_hash": "aa" * 32, "tx_pos": 0, "height": 800000, "value": 100000},
        {"tx_hash": "bb" * 32, "tx_pos": 1, "height": 0, "value": 52500},
    ],
    "blockchain.scripthash.get_history": [
        {"tx_hash": "cc" * 32, "height": 799999},
    ],
    "blockchain.scripthash.subscribe": "history-status",
}

ADDR = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
ADDR2 = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        for raw in self.rfile:
            req = json.loads(raw)
            if isinstance(req, list):
                reply = [{"id": r["id"], "result": _RESPONSES[r["method"]], "error": None}
                         for r in req]
            else:
                reply = {"id": req["id"], "result": _RESPONSES[req["method"]], "error": None}
            self.wfile.write(json.dumps(reply).encode() + b"\n")
            self.wfile.flush()


@pytest.fixture()
def server():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host = str(srv.server_address[0])
    port = int(srv.server_address[1])
    try:
        yield ChainQuery(host=host, port=port)
    finally:
        srv.shutdown()
        srv.server_close()


def test_get_balance(server):
    assert server.get_balance(ADDR) == Balance(150000, 2500)
    assert server.get_balance(ADDR).total == 152500


def test_get_utxos(server):
    utxos = server.get_utxos(ADDR)
    assert utxos == [
        Utxo("aa" * 32, 0, 100000, 800000),
        Utxo("bb" * 32, 1, 52500, 0),
    ]


def test_get_history(server):
    assert server.get_history(ADDR) == [HistoryEntry("cc" * 32, 799999)]


def test_batched_balances_map_by_address(server):
    balances = server.get_balances([ADDR, ADDR2])
    assert set(balances) == {ADDR, ADDR2}
    assert balances[ADDR] == Balance(150000, 2500)


def test_single_and_batched_statuses(server):
    assert server.get_status(ADDR) == "history-status"
    assert server.get_statuses([ADDR, ADDR2]) == {
        ADDR: "history-status",
        ADDR2: "history-status",
    }


def test_empty_batches_do_not_connect():
    chain = ChainQuery(host="127.0.0.1", port=1, timeout=0.01)
    assert chain.get_balances([]) == {}
    assert chain.get_utxos_many([]) == {}
    assert chain.get_history_many([]) == {}
    assert chain.get_statuses([]) == {}
