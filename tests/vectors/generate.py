"""Freeze test vectors from the libraries bitwalkit replaces.

Run this in an environment where the *originals* are importable -- i.e. the
Odoo venv (which has ``btclib``) with the vendored Electrum package on the path::

    PYTHONPATH=/home/elmeri/Odoo/src/19/tabularium/bitcoin_treasury \\
        /home/elmeri/.venv/odoo19/bin/python tests/vectors/generate.py

It writes ``generated.json`` next to this file. The committed test
(``test_upstream_vectors.py``) then checks bitwalkit against that frozen file
with *no* dependency on btclib or Electrum. Regenerate only when you want to
re-derive the oracle values; review the diff when you do.

Sources:
  * BIP32 derivation + serialization + fingerprint  -> btclib
  * P2PKH/P2SH-P2WPKH/P2WPKH/P2TR address derivation -> btclib.ScriptPubKey
  * Electrum-protocol scripthash                     -> vendored Electrum
"""

from __future__ import annotations

import json
import os

from btclib.bip32 import derive, xpub_from_xprv
from btclib.script.script_pub_key import ScriptPubKey
from btclib.to_pub_key import fingerprint

try:
    from electrum.bitcoin import address_to_scripthash as electrum_scripthash
except Exception:  # pragma: no cover - electrum path not provided
    electrum_scripthash = None

# BIP32 test-vector-1 root (mnemonic-independent, well known).
ROOT_XPRV = (
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKm"
    "PGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
)

# purpose -> script type, mirroring BIP44/49/84/86.
PURPOSES = {44: "p2pkh", 49: "p2sh-p2wpkh", 84: "p2wpkh", 86: "p2tr"}


def _address(script_type: str, xkey: str) -> str:
    if script_type == "p2pkh":
        return ScriptPubKey.p2pkh(xkey).address
    if script_type == "p2wpkh":
        return ScriptPubKey.p2wpkh(xkey).address
    if script_type == "p2tr":
        return ScriptPubKey.p2tr(xkey).address
    if script_type == "p2sh-p2wpkh":
        redeem = ScriptPubKey.p2wpkh(xkey).script
        return ScriptPubKey.p2sh(redeem).address
    raise KeyError(script_type)


def build() -> dict:
    out: dict = {
        "_source": "btclib + vendored Electrum (see generate.py)",
        "root_xprv": ROOT_XPRV,
        "bip32_chain": [],
        "accounts": [],
        "scripthashes": [],
    }

    # 1. BIP32 chain: hardened + non-hardened serialization / pubkey parity.
    for path in ["0'", "0'/1", "0'/1/2'", "0'/1/2'/2", "0'/1/2'/2/1000000000"]:
        child_xprv = derive(ROOT_XPRV, path)
        out["bip32_chain"].append(
            {
                "path": path,
                "xprv": child_xprv,
                "fingerprint": fingerprint(child_xprv, "mainnet").hex(),
            }
        )

    # 2. Account-level address derivation for every script type.
    addr_corpus: list[str] = []
    for purpose, script_type in PURPOSES.items():
        account_path = f"{purpose}'/0'/0'"
        account_xprv = derive(ROOT_XPRV, account_path)
        # Neuter to the account xpub via btclib (public key, xpub version).
        account_xpub = _xpub_from_xprv(account_xprv)
        rows = []
        for change in (0, 1):
            for index in (0, 1, 2, 5, 100):
                child = derive(account_xprv, f"{change}/{index}")
                address = _address(script_type, child)
                rows.append({"change": change, "index": index, "address": address})
                addr_corpus.append(address)
        out["accounts"].append(
            {
                "purpose": purpose,
                "script_type": script_type,
                "account_path": account_path,
                "account_xpub": account_xpub,
                "addresses": rows,
            }
        )

    # 3. Scripthashes for the whole address corpus, from vendored Electrum.
    if electrum_scripthash is not None:
        for address in addr_corpus:
            out["scripthashes"].append(
                {"address": address, "scripthash": electrum_scripthash(address)}
            )
    else:
        out["scripthashes"] = "SKIPPED: electrum not importable"

    return out


def _xpub_from_xprv(xprv: str) -> str:
    return xpub_from_xprv(xprv)


if __name__ == "__main__":
    data = build()
    dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated.json")
    with open(dest, "w") as fh:
        json.dump(data, fh, indent=2)
        fh.write("\n")
    print(f"wrote {dest}")
    print(
        f"bip32_chain={len(data['bip32_chain'])} "
        f"accounts={len(data['accounts'])} "
        f"scripthashes={len(data['scripthashes']) if isinstance(data['scripthashes'], list) else data['scripthashes']}"
    )
