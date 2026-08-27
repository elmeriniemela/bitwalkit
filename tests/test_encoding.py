"""Base58Check and bech32/bech32m encode/decode, and address <-> script."""

import pytest

import bitwalkit as bw
from bitwalkit.encoding import (
    base58check_decode,
    base58check_encode,
    bech32_decode,
    bech32_encode,
)
from bitwalkit.errors import EncodingError

# (address, expected scriptPubKey hex)
ADDRESSES = [
    ("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
     "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
    ("3P14159f73E4gFr7JterCCQh9QjiTjiZrG",
     "a914e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a87"),
    ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
     "0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"),
    ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
     "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"),
]


@pytest.mark.parametrize("addr,script_hex", ADDRESSES)
def test_address_to_script(addr, script_hex):
    assert bw.address_to_script(addr).hex() == script_hex


def test_base58check_roundtrip():
    for payload in (b"\x00" + b"\x11" * 20, b"\x05" + b"\xff" * 20, b"\x00\x00\x01\x02"):
        assert base58check_decode(base58check_encode(payload)) == payload


def test_bech32_roundtrip_v0_and_v1():
    for witver, prog in ((0, b"\x11" * 20), (0, b"\x22" * 32), (1, b"\x33" * 32)):
        enc = bech32_encode("bc", witver, prog)
        hrp, dv, dp = bech32_decode(enc)
        assert (hrp, dv, dp) == ("bc", witver, prog)


def test_reject_bad_base58_checksum():
    good = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
    bad = good[:-1] + ("A" if good[-1] != "A" else "B")
    with pytest.raises(EncodingError):
        base58check_decode(bad)


def test_reject_mixed_case_bech32():
    with pytest.raises(EncodingError):
        bech32_decode("bc1QCr8te4kr609gcawutmrza0j4xv80jy8z306fyu")


def test_reject_wrong_bech32_constant():
    # A v1 (taproot) program must use bech32m; re-encoding it as bech32 (v0
    # constant) must fail to decode.
    prog = b"\x33" * 32
    v0_encoded = bech32_encode("bc", 0, prog)  # valid bech32
    tampered = "bc1p" + v0_encoded[4:]  # claim witness version 1 (p) w/ bech32 const
    with pytest.raises(EncodingError):
        bech32_decode(tampered)


def test_p2pk_is_not_misrepresented_as_an_address():
    pubkey = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    with pytest.raises(EncodingError):
        bw.address_from_pubkey(pubkey, "p2pk")
