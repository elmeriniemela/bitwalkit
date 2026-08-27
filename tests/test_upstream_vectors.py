"""Parity against frozen Bitcoin wallet protocol reference vectors.

``vectors/generated.json`` contains BIP32/44/49/84/86 address and Electrum
scripthash fixtures. ``vectors/bip341_wallet_vectors.json`` is the canonical
Bitcoin Core BIP341 taproot vector file. Tests use only checked-in data and
have no optional runtime dependencies.
"""

import json
from pathlib import Path

import pytest

import bitwalkit as bw
from bitwalkit.address import p2tr_script

_VEC = Path(__file__).parent / "vectors"
_GEN = json.loads((_VEC / "generated.json").read_text())
_BIP341 = json.loads((_VEC / "bip341_wallet_vectors.json").read_text())


# --------------------------------------------------------------------------- #
# Address and scripthash reference vectors
# --------------------------------------------------------------------------- #

_ADDR_CASES = [
    (acc["account_xpub"], acc["script_type"], row["change"], row["index"], row["address"])
    for acc in _GEN["accounts"]
    for row in acc["addresses"]
]


@pytest.mark.parametrize("xpub,script_type,change,index,expected", _ADDR_CASES,
                         ids=[f"{a['script_type']}/{r['change']}/{r['index']}"
                              for a in _GEN["accounts"] for r in a["addresses"]])
def test_address_derivation_matches_reference(xpub, script_type, change, index, expected):
    assert bw.Account(xpub, script_type=script_type).address(change, index) == expected


@pytest.mark.parametrize("row", _GEN["scripthashes"], ids=lambda r: r["address"])
def test_scripthash_matches_electrum(row):
    assert bw.address_to_scripthash(row["address"]) == row["scripthash"]


# --------------------------------------------------------------------------- #
# BIP341 canonical taproot vectors (key-path / no script tree = BIP86 shape)
# --------------------------------------------------------------------------- #

_TAPROOT_KEYPATH = [
    e for e in _BIP341["scriptPubKey"] if e["given"].get("scriptTree") is None
]


@pytest.mark.parametrize("entry", _TAPROOT_KEYPATH,
                         ids=[e["given"]["internalPubkey"][:12] for e in _TAPROOT_KEYPATH])
def test_bip341_keypath_scriptpubkey_and_address(entry):
    internal = bytes.fromhex(entry["given"]["internalPubkey"])  # x-only
    assert p2tr_script(internal).hex() == entry["expected"]["scriptPubKey"]
    assert bw.address_from_pubkey(internal, "p2tr") == entry["expected"]["bip350Address"]
