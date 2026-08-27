# bitwalkit — Bitcoin Wallet Toolkit

A small, **dependency-free** Bitcoin wallet toolkit with three jobs:

1. **RPC** — call a Bitcoin Core node over JSON-RPC (`NodeRPC`).
2. **Derivation** — derive addresses from master/account extended *public* keys,
   watch-only (`Account`, `MultisigAccount`).
3. **Balances** — fetch an address's balance / UTXOs / history (`ChainQuery`),
   backed by an Electrum server but exposed purely in terms of addresses.

It replaces the slivers of `tinyrpc`, `btclib`, and Electrum that the Odoo
`bitcoin_*` modules used. The only non-stdlib code is a vendored, pure-Python
copy of [`secp256k1lab`](https://github.com/secp256k1lab/secp256k1lab) for EC
point math — there are no pip dependencies.

## Install / run from source

```bash
pip install -e .
# or, without installing, just put src/ on PYTHONPATH — the vendored
# secp256k1lab is added to sys.path automatically.
```

## Usage

```python
import bitwalkit as bw

# 1. Node RPC (attribute access maps to RPC methods, like a proxy)
rpc = bw.NodeRPC("http://127.0.0.1:8332", "rpcuser", "rpcpassword")
block = rpc.getblock(rpc.getbestblockhash(), 2)
tx = rpc.getrawtransaction(txid, True)          # raises bw.RpcError on node error

# 2. Watch-only address derivation from an account xpub/ypub/zpub.
#    The SLIP-0132 prefix selects the script type (override for taproot).
acc = bw.Account("zpub6r...")                    # -> p2wpkh (BIP84)
acc.receive_address(0)                           # m/.../0/0
acc.change_address(3)                            # m/.../1/3
acc.addresses(change=0, count=20)                # a gap-limit run

tr = bw.Account("xpub6B...", script_type="p2tr") # BIP86 taproot
ms = bw.MultisigAccount(["zpub...", "zpub..."], m=2, script_type="p2wsh")

# 3. Balances / UTXOs — caller only deals in addresses
chain = bw.ChainQuery("electrum.example.com", port=50002, use_ssl=True)
bal = chain.get_balance(acc.receive_address(0))  # Balance(confirmed, unconfirmed)
utxos = chain.get_utxos(acc.receive_address(0))  # [Utxo(txid, vout, value, height)]
chain.get_balances(acc.addresses(0, 20))         # batched, {address: Balance}
```

Supported address types: `p2pkh` (BIP44), `p2sh-p2wpkh` (BIP49), `p2wpkh`
(BIP84), `p2tr` (BIP86), and `p2wsh` / `p2sh-p2wsh` multisig (BIP48, BIP67
key sorting). Mainnet, testnet, and regtest.

## Tests

```bash
python -m pytest
```

Coverage:

- Encode/decode round-trips and malformed-input rejection.
- BIP32/44/49/84/86 derivation against the official test vectors.

Regenerate the frozen vectors (only when intentionally re-deriving them) in an
environment that has the originals installed:

