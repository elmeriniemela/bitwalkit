"""Make concurrent Bitcoin Core RPC calls with one shared NodeRPC client."""

from concurrent.futures import ThreadPoolExecutor

from bitwalkit import NodeRPC


rpc = NodeRPC("http://127.0.0.1:8332", "rpcuser", "rpcpassword")

# Both calls use the same client and run concurrently in separate worker threads.
# NodeRPC gives each call its own request ID, so out-of-order replies are safe.
with ThreadPoolExecutor(max_workers=2) as pool:
    height = pool.submit(rpc.getblockcount)
    network = pool.submit(rpc.getnetworkinfo)

    # result() waits for each call and either returns its value or raises its error.
    print("Block height:", height.result())
    print("Node version:", network.result()["subversion"])
