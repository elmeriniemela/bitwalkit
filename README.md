# bitwalkit — Watch-only Bitcoin wallet toolkit

`bitwalkit` is a standalone, dependency-free Python toolkit for deriving and
monitoring Bitcoin watch-only wallets. It handles public wallet data only: the
library does not accept private extended keys, hold secrets, or sign
transactions.

Its public API covers four tasks:

1. Derive single-signature and multisignature addresses from extended public
   keys with `Account` and `MultisigAccount`.
2. Query address balances, UTXOs, and transaction history through an Electrum
   server with `ChainQuery`.
3. Call a Bitcoin Core node over JSON-RPC with `NodeRPC`.
4. Construct native SegWit PSBTs offline from manually declared inputs with
   `derive_native_segwit` and `create_psbt`.
5. Parse legacy and SegWit transaction HEX locally with `parse_transaction`.

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

Install the latest release from PyPI:

```bash
python -m pip install bitwalkit
```

For development, clone and install from the repository root:

```bash
git clone https://github.com/elmeriniemela/bitwalkit.git
cd bitwalkit
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

`NodeRPC` supports concurrent calls and batches while its configuration remains
unchanged. Single-call request IDs are allocated under a short lock, while batch
IDs remain local to their HTTP request. Network I/O is not serialized, so a
long-polling request does not block other calls on the client.
Address derivation and encoding are fully local.

### Transaction HEX parsing

`parse_transaction` decodes a complete raw transaction into immutable typed
inputs and outputs. It also calculates the transaction's `txid`, `wtxid`, byte
size, weight, and virtual size. The original string is retained as `tx.hex` for
direct use with RPC methods.

```python
tx = bw.parse_transaction(raw_transaction_hex)
print(tx.txid, tx.version, tx.locktime)
node.sendrawtransaction(tx.hex)
for output in tx.outputs:
    print(output.amount, output.script_pubkey.hex())
```

Legacy and SegWit serialization are supported. Scripts and witness elements
remain raw bytes, so parsing does not require or assume a network. This checks
the serialized encoding; it does not validate scripts, signatures, amounts,
UTXO existence, or consensus and relay rules.

### Offline PSBT generation

`create_psbt` returns binary [PSBT v0 (BIP 174)](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
data. Inputs can reference any outpoint, including unknown or spent outputs.
No balance, transaction history, or UTXO lookup is performed. All amounts are
integer satoshis, and the difference between input and output totals is the
fee. Outputs cannot exceed declared inputs; zero amounts and zero fees are
allowed without dust or fee-rate checks.

```python
import base64
from pathlib import Path
from bitwalkit import (
    KeyOrigin, PSBTInput, PSBTOutput, address_to_script,
    create_psbt, derive_native_segwit,
)

# Supply the account xpub, master fingerprint, and full account origin from
# your signing wallet. The origin depth must match the extended key's depth.
keys = [(account_xpub, KeyOrigin.parse(master_fingerprint, "m/84h/0h/0h"))]
source = derive_native_segwit(keys, change=0, index=50)
change = derive_native_segwit(keys, change=1, index=3)
psbt = create_psbt(
    [PSBTInput(previous_txid, output_index=0, amount=100_000, spend=source)],
    [PSBTOutput(60_000, address_to_script(recipient, network="mainnet")),
     PSBTOutput(39_000, change.script_pubkey, spend=change)],
)
Path("transaction.psbt").write_bytes(psbt)
print(base64.b64encode(psbt).decode("ascii"))
```

To include data in an OP_RETURN output, add a zero-valued output without signing
metadata to the output list:

```python
from bitwalkit import PSBTOutput, op_return_script

data_output = PSBTOutput(0, op_return_script(b"hello"))
```

`op_return_script` accepts bytes and preserves them as a single data push;
empty bytes produce `6a00`. Encode text explicitly with `.encode("utf-8")`, or
decode hexadecimal with `bytes.fromhex(...)`. The helper supports larger push
encodings and does not impose a relay-policy payload limit; acceptance depends
on the receiving node's policy. Its dust threshold is zero.

One key derives P2WPKH. With 2–15 keys, pass `threshold=2` (or the desired
threshold) to derive BIP67-sorted P2WSH. A master xpub can use `None` as its
origin: its fingerprint and empty path are derived automatically. All other
keys require a `KeyOrigin`. Input and wallet-output metadata include public
key derivations, account xpub origins, and multisig witness scripts.

The unsigned transaction defaults to version 2, locktime 0, final input
sequences, and SIGHASH_ALL. Input `sequence` and builder `version`/`locktime`
can be supplied explicitly. Use `InputSequence` for common sequence values:

```python
from bitwalkit import InputSequence, PSBTInput

source_input = PSBTInput(
    previous_txid, output_index=0, amount=100_000, spend=source,
    sequence=InputSequence.RBF,
)
```

| Preset | Value | Meaning |
| --- | --- | --- |
| `InputSequence.FINAL` (default) | `0xFFFFFFFF` | Ignores transaction locktime when used by every input; no explicit RBF signal. |
| `InputSequence.LOCKTIME` | `0xFFFFFFFE` | Enables transaction locktime without explicit RBF signaling. |
| `InputSequence.RBF` | `0xFFFFFFFD` | Enables transaction locktime and explicitly signals RBF. |

All three presets disable relative locktime. Set `create_psbt(..., locktime=...)`
to specify the desired absolute locktime; presets do not change the builder's
locktime or version. Under [BIP 125](https://bips.dev/125/), any input with a
sequence below `0xFFFFFFFE` explicitly signals replacement, and signaling can
also be inherited from unconfirmed ancestors. Absence of a signal does not
guarantee that a transaction cannot be replaced: Bitcoin Core 28 enabled full
RBF by default ([release notes](https://bitcoincore.org/en/releases/28.0/)).

Plain integers from `0` through `0xFFFFFFFF` remain accepted, including custom
[BIP 68](https://bips.dev/68/) relative delays. For transaction versions at least
2, clearing bit 31 enables relative locktime; the low 16 bits encode a delay
in blocks, or in 512-second units when bit 22 is set. For example, `sequence=144`
encodes a 144-block delay, and `sequence=(1 << 22) | 7` encodes 3,584 seconds
measured using median time past. Zero encodes no relative delay. Leave reserved
bits clear when constructing these encodings. These relative-delay values also
explicitly signal BIP 125 replacement. [BIP 112](https://bips.dev/112/) allows
scripts to check relative-locktime constraints; this builder's supported script
types remain P2WPKH and sorted-multisig P2WSH.

This API does not sign, finalize, or broadcast.
Supplied input amounts and scripts must match the actual previous outputs for
a transaction to be spendable. Some signers require full previous transactions;
this builder supplies witness UTXOs only. Legacy and Taproot inputs are not
supported by the PSBT builder.

For an optional output-policy warning, `dust_threshold(script_pubkey)` returns
the threshold in satoshis using Bitcoin Core's spend-size model and a baseline
`dust_relay_fee=3000` sat/kvB. For example, P2WPKH is 294 sat and P2WSH/P2TR
are 330 sat at that baseline; an amount equal to the threshold is not dust.
This helper does not query a node or alter `create_psbt` validation. Actual
relay policies can differ. The reference calculation is
[Core's GetDustThreshold](https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.cpp).

## Tests

```bash
python -m pytest
python -m pyright
```

The suite covers malformed input handling, BIP32 public derivation, address
encoding, BIP44/49/84/86 derivation, BIP341 taproot vectors, multisig,
Electrum protocol behavior, Bitcoin Core JSON-RPC response handling, and PSBT
serialization and metadata. Transaction parsing is checked against public
BIP143/BIP341 and Bitcoin Core vectors, including the genesis coinbase and
CompactSize boundary data. If `bitcoind` and `bitcoin-cli` are on `PATH`, PSBT
tests also decode generated files with an isolated regtest node; no existing
node configuration or wallet is used. Otherwise those interoperability tests
are skipped, while the frozen reference and serialization tests still run.

Additional coverage uses the upstream Bitcoin Core creator vector, published
BIP84 receive/change keys and origins, uint32 limits, malformed signing keys,
case-insensitive duplicate inputs, and dust-policy boundaries. When Core is
available, it signs and finalizes single-signature and multisig fixtures using
only publicly documented BIP84 test keys; those transactions are never broadcast.

When `btclib` is installed, `python -m pytest tests/test_btclib_fuzz.py -q`
runs deterministic differential fuzz tests for native SegWit derivation, PSBT
serialization and metadata, CompactSize boundaries, and Base58 address validation.
Each random seed is a separate test case for reproducibility. The module skips
automatically without `btclib`; it is not a runtime dependency. Global xpub
validation and dust fee rounding regression tests also run without `btclib`.

## License

MIT. See [COPYING](COPYING).
