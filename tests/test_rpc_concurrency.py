"""Requests sharing a client must retain their own IDs across blocking I/O."""

from concurrent.futures import ThreadPoolExecutor
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from bitwalkit import ConnectionError, NodeRPC, RpcError


class ConcurrentRPC(NodeRPC):
    def __init__(self, responder):
        super().__init__('http://unused.invalid')
        self.responder = responder

    def _post(self, payload):
        return self.responder(json.loads(payload))


@pytest.mark.parametrize('error', [False, True])
def test_long_poll_id_109_survives_concurrent_broadcast(error):
    waiting, release = threading.Event(), threading.Event()
    def respond(req):
        if req['method'] == 'waitfornewblock':
            assert req['id'] == 109
            waiting.set()
            assert release.wait(5)
            if error:
                return {'id': req['id'], 'error': {'code': -28, 'message': 'warming up'}}
            return {'id': req['id'], 'result': {'hash': 'tip', 'height': 42}}
        assert req['id'] == 110
        return {'id': req['id'], 'result': 'high-txid'}
    rpc = ConcurrentRPC(respond)
    rpc._id = 108
    with ThreadPoolExecutor(max_workers=2) as pool:
        poll = pool.submit(rpc.waitfornewblock, 2000, 'tip')
        try:
            assert waiting.wait(5)
            # Must finish BEFORE releasing the long poll (no transport-wide lock).
            broadcast = pool.submit(rpc.sendrawtransaction, 'hex')
            assert broadcast.result(timeout=5) == 'high-txid'
        finally:
            release.set()
        if error:
            with pytest.raises(RpcError, match='warming up') as exc:
                poll.result(timeout=5)
            assert exc.value.code == -28
        else:
            assert poll.result(timeout=5) == {'hash': 'tip', 'height': 42}


def test_concurrent_requests_have_unique_ids_and_reversed_responses():
    count = 12
    barrier = threading.Barrier(count)
    releases = [threading.Event() for _ in range(count)]
    records = []
    records_lock = threading.Lock()
    def respond(req):
        with records_lock:
            records.append(req['id'])
        barrier.wait(timeout=5)
        assert releases[req['params'][0]].wait(5)
        return {'id': req['id'], 'result': req['params'][0]}
    rpc = ConcurrentRPC(respond)
    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [pool.submit(rpc.call, 'echo', i) for i in range(count)]
        try:
            for i in reversed(range(count)):
                releases[i].set()
                assert futures[i].result(timeout=5) == i
        finally:
            for event in releases:
                event.set()
    assert sorted(records) == list(range(1, count + 1))


@pytest.mark.parametrize('mismatch', [None, 999, '1'])
def test_genuine_mismatch_reports_expected_and_received(mismatch):
    rpc = ConcurrentRPC(lambda req: {'id': mismatch, 'result': True})
    with pytest.raises(RpcError) as exc:
        rpc.getblockcount()
    assert 'expected 1' in str(exc.value)
    assert f'received {mismatch!r}' in str(exc.value)


def test_failed_request_id_is_not_reused():
    seen = []

    def respond(req):
        seen.append(req['id'])
        if req['method'] == 'first':
            raise ConnectionError('connection dropped')
        return {'id': req['id'], 'result': 'ok'}

    rpc = ConcurrentRPC(respond)
    with pytest.raises(ConnectionError, match='connection dropped'):
        rpc.call('first')
    assert rpc.call('second') == 'ok'
    assert seen == [1, 2]


def test_overlapping_batches_and_single_calls_are_independent():
    barrier = threading.Barrier(3)
    def respond(req):
        barrier.wait(timeout=5)
        if isinstance(req, list):
            return [{'id': item['id'], 'result': item['method']} for item in reversed(req)]
        return {'id': req['id'], 'result': req['method']}
    rpc = ConcurrentRPC(respond)
    with ThreadPoolExecutor(max_workers=3) as pool:
        a = pool.submit(rpc.batch, [('a',), ('b',)])
        b = pool.submit(rpc.batch, [('c',), ('d',)])
        single = pool.submit(rpc.call, 'single')
        assert a.result(timeout=5) == ['a', 'b']
        assert b.result(timeout=5) == ['c', 'd']
        assert single.result(timeout=5) == 'single'


def test_http_broadcast_finishes_while_long_poll_is_blocked():
    waiting, release = threading.Event(), threading.Event()
    requests = []
    lock = threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            with lock:
                requests.append(req)
            if req['method'] == 'waitfornewblock':
                waiting.set()
                if not release.wait(5):
                    self.send_error(500)
                    return
                result = {'hash': 'tip', 'height': 42}
            else:
                result = 'high-txid'
            body = json.dumps({'id': req['id'], 'result': result}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    rpc = NodeRPC(f'http://127.0.0.1:{server.server_port}', timeout=5)
    rpc._id = 108
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            poll = pool.submit(rpc.waitfornewblock, 2000, 'tip')
            try:
                assert waiting.wait(5)
                broadcast = pool.submit(rpc.sendrawtransaction, 'hex')
                assert broadcast.result(timeout=5) == 'high-txid'
                assert not poll.done()
            finally:
                release.set()
            assert poll.result(timeout=5) == {'hash': 'tip', 'height': 42}
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert [(req['method'], req['id']) for req in requests] == [
        ('waitfornewblock', 109), ('sendrawtransaction', 110)]
