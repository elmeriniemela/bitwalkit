"""Raw legacy and SegWit transaction parsing."""

import json
from pathlib import Path

import pytest

from bitwalkit import EncodingError, parse_transaction


PUBLIC_VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "transactions.json").read_text()
)["vectors"]


LEGACY_HEX = (
    "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da"
    "95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab"
    "47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3"
    "d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3"
    "d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a24"
    "8e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c"
    "019e756c88ac6acb0700"
)

SEGWIT_HEX = (
    "02000000000101" + "00" * 32 + "ffffffff0151fdffffff"
    "01e80300000000000001510300010102020300000000"
)


def test_parse_legacy_transaction_fields_and_metrics():
    tx = parse_transaction(LEGACY_HEX)
    assert tx.version == 2
    assert tx.locktime == 510826
    assert not tx.has_witness
    assert len(tx.inputs) == 1 and len(tx.outputs) == 2
    assert tx.inputs[0].previous_txid == (
        "95da344585fcf2e5f7d6cbf2c3df2dcce84f9196f7a7bb901a43275cd6eb7c3f"
    )
    assert tx.inputs[0].output_index == 0
    assert tx.inputs[0].script_sig.startswith(bytes.fromhex("483045"))
    assert tx.inputs[0].sequence == 0xFFFFFFFE
    assert tx.inputs[0].witness == ()
    assert [output.amount for output in tx.outputs] == [20_737_411, 42_130_042]
    assert all(output.script_pubkey.startswith(bytes.fromhex("76a914")) for output in tx.outputs)
    assert tx.txid == tx.wtxid
    assert tx.size == len(bytes.fromhex(LEGACY_HEX))
    assert tx.weight == tx.size * 4
    assert tx.vsize == tx.size


def test_parse_segwit_transaction_fields_ids_and_metrics():
    original_hex = SEGWIT_HEX.upper()
    tx = parse_transaction(original_hex)
    assert tx.version == 2 and tx.locktime == 0
    assert tx.hex == original_hex
    assert tx.has_witness
    assert tx.inputs[0].previous_txid == "00" * 32
    assert tx.inputs[0].output_index == 0xFFFFFFFF
    assert tx.inputs[0].script_sig == b"\x51"
    assert tx.inputs[0].sequence == 0xFFFFFFFD
    assert tx.inputs[0].witness == (b"", b"\x01", b"\x02\x03")
    assert tx.outputs[0].amount == 1000
    assert tx.outputs[0].script_pubkey == b"\x51"
    assert tx.txid == "2851afcb483846d1849192acacb785f90652f956f959b481911617c9f64f905a"
    assert tx.wtxid == "4d535e3901339ed54f8fa07878b640fe4a788d97b1d4c444cc20e0744ecf9dc7"
    assert (tx.size, tx.weight, tx.vsize) == (71, 257, 65)


@pytest.mark.parametrize("value", [None, b"00", 1, "", "0", "zz", "00 00"])
def test_reject_invalid_hex(value):
    with pytest.raises(EncodingError, match="HEX"):
        parse_transaction(value)


@pytest.mark.parametrize("raw", [
    "020000",  # truncated version
    "020000000001",  # truncated witness flag
    "020000000002",  # unknown witness flag
    "02000000000100",  # marker without inputs
    "02000000fd0100",  # noncanonical input count
    "02000000ff" + "ff" * 8,  # enormous input count
    "0200000001" + "00" * 31,  # truncated outpoint
    "0200000001" + "00" * 32 + "00000000fd0100",  # noncanonical script length
    "0200000001" + "00" * 32 + "0000000000ffffffff01",  # truncated output
    "0200000001" + "00" * 32 + "0000000000ffffffff00",  # truncated locktime
])
def test_reject_malformed_or_truncated_transactions(raw):
    with pytest.raises(EncodingError):
        parse_transaction(raw)


def test_reject_superfluous_witness_and_trailing_data():
    empty_witness = (
        "02000000000101" + "00" * 32 + "ffffffff00ffffffff"
        "010000000000000000000000000000"
    )
    with pytest.raises(EncodingError, match="Superfluous"):
        parse_transaction(empty_witness)
    with pytest.raises(EncodingError, match="trailing"):
        parse_transaction(LEGACY_HEX + "00")


def test_preserve_signed_output_and_coinbase_outpoint():
    raw = (
        "ffffffff01" + "00" * 32 + "ffffffff0100ffffffff"
        "01ffffffffffffffff0000000000"
    )
    tx = parse_transaction(raw)
    assert tx.hex == raw
    assert tx.version == 0xFFFFFFFF
    assert tx.inputs[0].previous_txid == "00" * 32
    assert tx.inputs[0].output_index == 0xFFFFFFFF
    assert tx.outputs[0].amount == -1


@pytest.mark.parametrize("row", PUBLIC_VECTORS, ids=lambda row: row["name"])
def test_public_transaction_vectors(row):
    tx = parse_transaction(row["hex"])
    expected = row["expected"]

    assert tx.hex == row["hex"]
    assert tx.version == expected["version"]
    assert len(tx.inputs) == expected["input_count"]
    assert len(tx.outputs) == expected["output_count"]
    assert tx.locktime == expected["locktime"]
    assert tx.has_witness == expected["has_witness"]
    assert tx.txid == expected["txid"]
    assert tx.wtxid == expected["wtxid"]
    assert (tx.size, tx.weight, tx.vsize) == (
        expected["size"], expected["weight"], expected["vsize"],
    )
    assert [len(item.script_sig) for item in tx.inputs] == expected["script_sig_lengths"]
    assert [[len(value) for value in item.witness] for item in tx.inputs] == \
        expected["witness_item_lengths"]
    assert [item.amount for item in tx.outputs] == expected["output_amounts"]
    assert [len(item.script_pubkey) for item in tx.outputs] == \
        expected["output_script_lengths"]


def test_public_vectors_cover_distinct_serialization_boundaries():
    parsed = {row["name"]: parse_transaction(row["hex"]) for row in PUBLIC_VECTORS}

    genesis = parsed["bitcoin-genesis-coinbase"]
    assert genesis.txid == "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    assert genesis.outputs[0].amount == 5_000_000_000
    assert b"The Times 03/Jan/2009" in genesis.inputs[0].script_sig

    assert len(parsed["bitcoin-core-long-output-script"].outputs[0].script_pubkey) == 258
    assert len(parsed["bitcoin-core-ambiguous-witness-coinbase"].inputs[0].witness) == 1
    assert len(parsed["bip341-key-path-unsigned"].inputs) == 9
    assert parsed["bip143-native-p2wpkh"].inputs[0].witness == ()
