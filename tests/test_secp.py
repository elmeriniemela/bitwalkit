"""Focused tests for the internal public-key-only secp256k1 arithmetic."""

import pytest

from bitwalkit._secp import G, GE
from bitwalkit.address import p2tr_script
from bitwalkit.errors import EncodingError

_G_COMPRESSED = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
_TWO_G_COMPRESSED = bytes.fromhex(
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)


def test_generator_serialization_and_lifting():
    assert G.to_bytes_compressed() == _G_COMPRESSED
    assert G.to_bytes_xonly() == _G_COMPRESSED[1:]
    assert GE.from_bytes_compressed(_G_COMPRESSED) == G
    assert G.x is not None
    assert GE.lift_x(G.x) == G


def test_point_addition_and_scalar_multiplication():
    two_g = GE.from_bytes_compressed(_TWO_G_COMPRESSED)
    assert G + G == two_g
    assert 2 * G == two_g
    assert 0 * G == GE()
    assert GE.ORDER * G == GE()
    assert (GE.ORDER + 1) * G == G


def test_compressed_key_parity_selects_opposite_points():
    even = GE.from_bytes_compressed(_G_COMPRESSED)
    odd = GE.from_bytes_compressed(b"\x03" + _G_COMPRESSED[1:])
    assert even != odd
    assert even + odd == GE()
    assert odd.to_bytes_compressed()[0] == 3


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"\x02" + b"\x00" * 31,
        b"\x04" + b"\x00" * 32,
        b"\x02" + b"\x00" * 32,
        b"\x02" + b"\xff" * 32,
    ],
)
def test_invalid_compressed_keys_are_rejected(encoded):
    with pytest.raises(ValueError):
        GE.from_bytes_compressed(encoded)


def test_invalid_points_and_infinity_serialization_are_rejected():
    with pytest.raises(ValueError):
        GE(1, 1)
    with pytest.raises(ValueError):
        GE().to_bytes_compressed()
    with pytest.raises(ValueError):
        GE().to_bytes_xonly()


def test_invalid_taproot_internal_key_is_an_encoding_error():
    with pytest.raises(EncodingError, match="invalid taproot internal key"):
        p2tr_script(b"\xff" * 32)
