"""Bitcoin Core descriptor checksum vectors frozen from btclib."""

import pytest

from bitwalkit import descriptor_checksum
from bitwalkit.errors import EncodingError


@pytest.mark.parametrize(("descriptor", "expected"), [
    ("raw(deadbeef)", "89f8spxm"),
    ("pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
     "gn28ywm7"),
    ("pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
     "e48zzw02"),
    ("wpkh([deadbeef/84h/0h/0h]xpub661MyMwAqRbcFfake/<0;1>/*)", "mprulyaz"),
    ("sh(wpkh(xpub661MyMwAqRbcFfake/0/*))", "a3r9qrte"),
    ("wsh(sortedmulti(2,xpubA/0/*,xpubB/0/*))", "z7555tcj"),
    ("addr(bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu)", "lpewvaaa"),
    ("tr(79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)",
     "gxjkeue2"),
])
def test_descriptor_checksum_vectors(descriptor, expected):
    assert descriptor_checksum(descriptor) == expected


def test_descriptor_checksum_rejects_non_ascii_input():
    with pytest.raises(EncodingError):
        descriptor_checksum("raw(€)")
