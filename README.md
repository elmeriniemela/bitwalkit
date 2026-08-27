# bitwalkit — Watch-only Bitcoin wallet toolkit

`bitwalkit` is a standalone, dependency-free Python toolkit for deriving and
monitoring Bitcoin watch-only wallets. It handles public wallet data only: the
library does not accept private extended keys, hold secrets, or sign
transactions.

Its public API covers three tasks:

1. Derive single-signature and multisignature addresses from extended public
   keys with `Account` and `MultisigAccount`.
2. Query address balances, UTXOs, and transaction history through an Electrum
   server with `ChainQuery`.
3. Call a Bitcoin Core node over JSON-RPC with `NodeRPC`.

The runtime uses only the Python standard library. A small, public-key-only
secp256k1 implementation validates compressed public keys, derives
non-hardened BIP32 child public keys, and applies the BIP341/BIP86 Taproot
output-key tweak. It is not suitable for private-key handling or transaction
signing. There are no packages to install at runtime.

## Supported wallets

- Single-key P2PKH (BIP44), P2SH-P2WPKH (BIP49), P2WPKH (BIP84), and P2TR
  (BIP86)
- P2WSH and P2SH-P2WSH multisig (BIP48), with optional BIP67 key sorting
- Mainnet, testnet, and regtest addresses
- BIP32 and SLIP-0132 public prefixes: xpub/tpub, ypub/upub, zpub/vpub, and the
  corresponding multisig prefixes

Only non-hardened children can be derived from an extended public key. Export
an account-level public key from the signing wallet before using this library.

## Install

Clone and install from the repository root:

```bash
git clone https://github.com/elmeriniemela/bitwalkit.git
cd bitwalkit
python -m pip install -e .
```

For development tools:

```bash
python -m pip install -e '.[dev]'
```

## Usage

```python
import bitwalkit as bw

# The SLIP-0132 prefix selects the default script type.
account = bw.Account("zpub6r...")
first_receive = account.receive_address(0)
first_change = account.change_address(0)
gap_limit = account.addresses(change=0, count=20)

# Pass script_type explicitly when xpub alone is ambiguous, as with BIP86.
taproot = bw.Account("xpub6B...", script_type="p2tr")

# Multisig derives the same change/index path for every cosigner.
multisig = bw.MultisigAccount(
    ["Zpub...", "Zpub...", "Zpub..."],
    m=2,
    script_type="p2wsh",
)

# Query public chain state by address.
chain = bw.ChainQuery("electrum.example.com", port=50002, use_ssl=True)
balance = chain.get_balance(first_receive)
utxos = chain.get_utxos(first_receive)
history = chain.get_history(first_receive)
balances = chain.get_balances(gap_limit)

# Optional direct Bitcoin Core RPC access.
node = bw.NodeRPC("http://127.0.0.1:8332", "rpcuser", "rpcpassword")
height = node.getblockcount()
```

Network access is performed only when calling `ChainQuery` or `NodeRPC`.
Address derivation and encoding are fully local.

## Tests

```bash
python -m pytest
python -m pyright
```

The suite covers malformed input handling, BIP32 public derivation, address
encoding, BIP44/49/84/86 derivation, BIP341 taproot vectors, multisig,
Electrum protocol behavior, and Bitcoin Core JSON-RPC response handling.

## License

MIT. See [COPYING](COPYING).
