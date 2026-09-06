"""Seeded differential fuzzing; skipped when the optional btclib is absent.

Run with ``python -m pytest tests/test_btclib_fuzz.py -q``. Each seed is a
separate pytest case, so failures can be reproduced with ``-k``. All private
keys below are generated from deterministic test data, never wallet secrets.
"""

from dataclasses import replace
import random

import pytest

pytest.importorskip("btclib")

from btclib.base58 import b58decode, b58encode
from btclib.bip32 import (
    BIP32KeyData, BIP32KeyOrigin, derive, rootxprv_from_seed, xpub_from_xprv,
)
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.psbt import Psbt, PsbtIn, PsbtOut
from btclib.script import ScriptPubKey, serialize as serialize_script
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from bitwalkit import (
    EncodingError, KeyOrigin, PSBTInput, PSBTOutput, address_to_script,
    create_psbt, derive_native_segwit, op_return_script,
)
from bitwalkit.psbt import MAX_MONEY


def _origin(origin):
    return BIP32KeyOrigin(origin.fingerprint, origin.path)


def _assert_psbt_matches(inputs, outputs, *, version=2, locktime=0):
    """Build the same transaction and maps using btclib's own serializers."""
    expected = Psbt(
        Tx(version, locktime,
           [TxIn(OutPoint(item.txid, item.output_index), sequence=item.sequence)
            for item in inputs],
           [TxOut(item.amount, item.script_pubkey) for item in outputs]),
        [PsbtIn(witness_utxo=TxOut(item.amount, item.spend.script_pubkey),
                sig_hash_type=1, witness_script=item.spend.witness_script,
                hd_key_paths={key: _origin(origin)
                              for key, origin in item.spend.derivations})
         for item in inputs],
        [PsbtOut(witness_script=item.spend.witness_script,
                 hd_key_paths={key: _origin(origin)
                               for key, origin in item.spend.derivations})
         if item.spend else PsbtOut() for item in outputs],
        version=0,
        hd_key_paths={key: _origin(origin) for item in (*inputs, *outputs)
                      if item.spend for key, origin in item.spend.xpubs},
    )
    raw = create_psbt(inputs, outputs, version=version, locktime=locktime)
    decoded = Psbt.parse(raw)
    decoded.assert_signable()
    assert decoded == expected
    assert raw == expected.serialize()
    assert decoded.serialize() == raw


@pytest.mark.parametrize("seed", range(20))
def test_fuzz_derivation_and_psbt_against_btclib(seed):
    rng = random.Random(seed)
    network = "testnet" if seed % 2 else "mainnet"
    count = (1, 2, 3, 5, 15)[seed % 5]
    threshold = rng.randint(1, count)
    branch = seed % 2
    index = (0, 1, 0x7FFFFFFF, rng.randrange(0x80000000))[seed % 4]
    # Exercise canonical and SLIP-0132 public versions on both networks.
    versions = ((0x0488B21E, 0x049D7CB2, 0x04B24746, 0x0295B43F, 0x02AA7ED3)
                if network == "mainnet" else
                (0x043587CF, 0x044A5262, 0x045F1CF6, 0x024289EF, 0x02575483))
    keys, expected_derivations, expected_xpubs, child_xpubs = [], {}, {}, []
    for _ in range(count):
        root = rootxprv_from_seed(
            rng.randbytes(32),
            version=bytes.fromhex("0488ade4" if network == "mainnet" else "04358394"),
        )
        fingerprint = hash160(BIP32KeyData.b58decode(xpub_from_xprv(root)).key)[:4]
        path = (() if seed % 3 == 0 else
                (0x80000054, 0x80000000 + (network == "testnet"),
                 0x80000000 + rng.randrange(1000)))
        account = xpub_from_xprv(derive(root, path))
        origin = KeyOrigin(fingerprint, path)
        encoded = derive(account, (), forced_version=rng.choice(versions).to_bytes(4, "big"))
        keys.append((encoded, origin if path else None))
        expected_xpubs[b58decode(account)] = origin
        child = derive(account, (branch, index))
        child_xpubs.append(child)
        pubkey = BIP32KeyData.b58decode(child).key
        expected_derivations[pubkey] = KeyOrigin(fingerprint, path + (branch, index))
    rng.shuffle(keys)
    spend = derive_native_segwit(keys, branch, index, threshold=threshold)
    witness = (ScriptPubKey.p2ms(threshold, list(expected_derivations),
                               network=network, compressed=True).script
               if count > 1 else b"")
    script = (ScriptPubKey.p2wsh(witness, network=network) if witness else
              ScriptPubKey.p2wpkh(child_xpubs[0]))
    assert spend.script_pubkey == script.script
    assert spend.address == script.address
    assert spend.witness_script == witness
    assert spend.derivations == tuple(sorted(expected_derivations.items()))
    assert dict(spend.xpubs) == expected_xpubs
    assert address_to_script(script.address, network) == script.script
    _assert_psbt_matches(
        [PSBTInput(rng.randbytes(32).hex(), rng.randrange(0xFFFFFFFF), 100_000, spend)],
        [PSBTOutput(99_000, spend.script_pubkey, spend)],
    )


@pytest.fixture(scope="module")
def spends():
    roots = [xpub_from_xprv(rootxprv_from_seed(bytes([i]) * 32)) for i in (1, 2, 3)]
    return (
        derive_native_segwit([(roots[0], None)], 0, 0),
        derive_native_segwit([(root, None) for root in roots], 1, 0x7FFFFFFF, threshold=2),
    )


@pytest.mark.parametrize("seed", range(48))
def test_fuzz_transaction_fields_against_btclib(spends, seed):
    rng = random.Random(seed)
    # btclib caps individual amounts at the mined supply, below Core's
    # 21M BTC MAX_MONEY. The exact MAX_MONEY case is covered in test_psbt.py.
    maximum = MAX_MONEY - 100_000_000
    total = (0, 1, maximum, rng.randrange(maximum + 1))[seed % 4]
    inputs = []
    remaining = total
    for i in range(rng.randint(1, 5)):
        amount = rng.randrange(remaining + 1)
        remaining -= amount
        inputs.append(PSBTInput(
            rng.randbytes(32).hex().upper(), i, amount, rng.choice(spends),
            sequence=rng.choice((0, 0xFFFFFFFF, 0xFFFFFFFD, rng.getrandbits(32))),
        ))
    inputs[-1] = replace(inputs[-1], amount=inputs[-1].amount + remaining)
    outputs = []
    remaining = total
    for _ in range(rng.randint(1, 5)):
        amount = rng.randrange(remaining + 1)
        remaining -= amount
        spend = rng.choice(spends)
        outputs.append(PSBTOutput(amount, spend.script_pubkey,
                                  spend if rng.getrandbits(1) else None))
    _assert_psbt_matches(inputs, outputs,
                         version=rng.choice((0, 1, 2, 0x7FFFFFFF)),
                         locktime=rng.choice((0, 0xFFFFFFFF, rng.getrandbits(32))))


@pytest.mark.parametrize("count", [252, 253, 254])
def test_compact_size_counts_against_btclib(spends, count):
    spend = spends[0]
    _assert_psbt_matches(
        [PSBTInput("12" * 32, i, 1, spend) for i in range(count)],
        [PSBTOutput(1, spend.script_pubkey, spend) for _ in range(count)],
    )


@pytest.mark.parametrize("size", [252, 253, 254, 65535, 65536])
def test_compact_size_scripts_against_btclib(spends, size):
    _assert_psbt_matches([PSBTInput("12" * 32, 0, 1, spends[0])],
                         [PSBTOutput(0, b"\x6a" + b"\x00" * (size - 1))])


@pytest.mark.parametrize("seed", range(24))
def test_fuzz_op_return_against_btclib(spends, seed):
    rng = random.Random(seed)
    # btclib's nulldata helper caps payloads at 80 bytes; its general script
    # serializer permits up to 520. Larger encodings have explicit vectors.
    boundary = (0, 1, 75, 76, 80, 255, 256, 520)[seed % 8]
    for size in (boundary, rng.randrange(521)):
        payload = rng.randbytes(size)
        script = op_return_script(payload)
        assert script == serialize_script(["OP_RETURN", payload])
        if size <= 80:
            assert script == ScriptPubKey.nulldata(payload).script
        _assert_psbt_matches(
            [PSBTInput(rng.randbytes(32).hex(), 0, 100_000, spends[0])],
            [PSBTOutput(60_000, spends[0].script_pubkey),
             PSBTOutput(0, script),
             PSBTOutput(39_000, spends[1].script_pubkey, spends[1])],
        )


@pytest.mark.parametrize("seed", range(32))
def test_fuzz_base58_address_payloads_against_btclib(seed):
    rng = random.Random(seed)
    version = rng.choice((0, 5, 111, 196))
    for size in (0, 1, 19, 20, 21, 32, rng.randrange(2, 100)):
        address = b58encode(bytes([version]) + rng.randbytes(size)).decode("ascii")
        if size == 20:
            assert address_to_script(address) == ScriptPubKey.from_address(address).script
        else:
            with pytest.raises(BTClibValueError):
                ScriptPubKey.from_address(address)
            with pytest.raises(EncodingError):
                address_to_script(address)


@pytest.mark.parametrize("mutation", ["private", "off_curve", "version"])
def test_reject_invalid_global_xpub_metadata(spends, mutation):
    spend = spends[0]
    raw, origin = spend.xpubs[0]
    if mutation == "private":
        raw = b58decode(rootxprv_from_seed(bytes([1]) * 32))
        assert BIP32KeyData.parse(raw).is_private
    else:
        raw = (raw[:45] + b"\x02" + b"\xff" * 32 if mutation == "off_curve"
               else b"\xff" * 4 + raw[4:])
        with pytest.raises(BTClibValueError):
            BIP32KeyData.parse(raw)
    malformed = replace(spend, xpubs=((raw, origin),))
    with pytest.raises(EncodingError):
        create_psbt([PSBTInput("12" * 32, 0, 1, malformed)],
                    [PSBTOutput(1, spend.script_pubkey)])
