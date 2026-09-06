"""OP_RETURN byte-vector encoding and public API validation."""

import pytest

from bitwalkit import EncodingError, dust_threshold, op_return_script


@pytest.mark.parametrize("data,expected", [
    (b"", "6a00"),
    (b"hello", "6a0568656c6c6f"),
    (b"\x00", "6a0100"),
    (b"\x01", "6a0101"),
    (b"\x81", "6a0181"),
    (b"\xff\x00\x6a\x4c", "6a04ff006a4c"),
])
def test_op_return_vectors(data, expected):
    assert op_return_script(data) == bytes.fromhex(expected)


@pytest.mark.parametrize("size,prefix", [
    (74, "6a4a"), (75, "6a4b"), (76, "6a4c4c"), (77, "6a4c4d"),
    (254, "6a4cfe"), (255, "6a4cff"), (256, "6a4d0001"), (257, "6a4d0101"),
    (65534, "6a4dfeff"), (65535, "6a4dffff"),
    (65536, "6a4e00000100"), (65537, "6a4e01000100"),
])
def test_op_return_push_length_boundaries(size, prefix):
    data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
    script = op_return_script(data)
    assert script == bytes.fromhex(prefix) + data
    assert dust_threshold(script) == 0


@pytest.mark.parametrize("data", ["hello", "deadbeef", None, 1, [1],
                                 bytearray(b"hello"), memoryview(b"hello")])
def test_op_return_rejects_non_bytes(data):
    with pytest.raises(EncodingError, match="must be bytes"):
        op_return_script(data)


def test_op_return_rejects_unrepresentable_length():
    class OversizedBytes(bytes):
        def __len__(self):
            return 0x100000000

    # Exercise the format limit without allocating four GiB of test data.
    with pytest.raises(EncodingError, match="uint32"):
        op_return_script(OversizedBytes())
