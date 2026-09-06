"""PSBT construction, including independent Bitcoin Core interoperability."""

import base64
from dataclasses import replace
from decimal import Decimal
from enum import IntEnum
import io
import json
from pathlib import Path
import shutil
import socket
import subprocess

import pytest

from bitwalkit import (
    EncodingError, ExtendedKey, InputSequence, KeyOrigin, PSBTInput, PSBTOutput, SegwitSpend,
    address_from_script, address_to_script, base58check_decode, base58check_encode,
    create_psbt, derive_native_segwit, descriptor_checksum, dust_threshold, p2ms_script,
    op_return_script,
)
from bitwalkit.address import p2wpkh_script, p2wsh_script
from bitwalkit.psbt import MAX_MONEY

ROOT = "xpub661MyMwAqRbcGFeMhhkrJL6Yj3YKQFNZQSM2BAvoMmhdjNKBh43n5v3c4YT5dFtjkirfhqQHMd22br7cHAQXAV8cZdicedZJkNweja4WWBK"
TXID = bytes(range(32)).hex()

# Public BIP84 test vectors (CC0), never use these published keys for funds.
# https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors
BIP84_ACCOUNT = 'zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs'
BIP84_ORIGIN = KeyOrigin.parse('73c5da0a', "m/84'/0'/0'")
BIP84_ADDRESSES = [
    (0, 0, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
     '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c',
     'KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d'),
    (0, 1, 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g',
     '03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77',
     'Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy'),
    (1, 0, 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el',
     '03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6',
     'KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF'),
]


def read_maps(data):
    """Small independent map reader; assertions also reject trailing garbage."""
    stream = io.BytesIO(data)
    assert stream.read(5) == b'psbt\xff'

    def size():
        first = stream.read(1)[0]
        if first < 253:
            return first
        return int.from_bytes(stream.read({253: 2, 254: 4, 255: 8}[first]), 'little')

    maps = []
    while stream.tell() < len(data):
        entries = {}
        while length := size():
            key = stream.read(length)
            assert key not in entries
            value = stream.read(size())
            entries[key] = value
        maps.append(entries)
    assert stream.tell() == len(data)
    return maps


@pytest.fixture
def spend():
    return derive_native_segwit([(ROOT, None)], 0, 5)


def test_single_signature_transaction_and_metadata(spend):
    item = PSBTInput(TXID, 0x12345678, 100_000, spend)
    assert item.sequence is InputSequence.FINAL
    raw = create_psbt([item],
                      [PSBTOutput(99_000, spend.script_pubkey)])
    global_map, source, destination = read_maps(raw)
    expected_tx = (b'\x02\x00\x00\x00\x01' + bytes(range(31, -1, -1))
                   + bytes.fromhex('7856341200ffffffff01b88201000000000016')
                   + spend.script_pubkey + b'\x00' * 4)
    assert global_map[b'\x00'] == expected_tx
    assert source[b'\x01'] == bytes.fromhex('a08601000000000016') + spend.script_pubkey
    assert source[b'\x03'] == bytes.fromhex('01000000')
    pubkey, origin = spend.derivations[0]
    assert source[b'\x06' + pubkey] == ExtendedKey.parse(ROOT).fingerprint + bytes.fromhex('0000000005000000')
    assert origin.path == (0, 5)
    assert len([key for key in global_map if key[0] == 1]) == 1
    assert not destination
    assert b'\x05' not in source


@pytest.mark.parametrize('preset,value,encoded', [
    (InputSequence.FINAL, 0xFFFFFFFF, 'ffffffff'),
    (InputSequence.LOCKTIME, 0xFFFFFFFE, 'feffffff'),
    (InputSequence.RBF, 0xFFFFFFFD, 'fdffffff'),
])
def test_sequence_presets_match_integer_serialization(spend, preset, value, encoded):
    item = PSBTInput(TXID, 0, 100, spend, sequence=preset)
    outputs = [PSBTOutput(100, spend.script_pubkey)]
    raw = create_psbt([item], outputs)
    assert raw == create_psbt([replace(item, sequence=value)], outputs)
    assert read_maps(raw)[0][b'\x00'][42:46] == bytes.fromhex(encoded)


@pytest.mark.parametrize('sequence', [
    0, 1, 144, 0xFFFF, (1 << 22) | 7, 0x0040FFFF,
    0x7FFFFFFF, 0x80000000, 0xABCDEF01, 0xFFFFFFFF,
])
def test_custom_integer_sequences(spend, sequence):
    raw = create_psbt([PSBTInput(TXID, 0, 100, spend, sequence=sequence)],
                      [PSBTOutput(100, spend.script_pubkey)])
    assert int.from_bytes(read_maps(raw)[0][b'\x00'][42:46], 'little') == sequence


def test_mixed_sequences_preserve_transaction_parameters(spend):
    sequences = [InputSequence.FINAL, InputSequence.LOCKTIME, InputSequence.RBF, 144]
    inputs = [PSBTInput(TXID, index, 100, spend, sequence=sequence)
              for index, sequence in enumerate(sequences)]
    outputs = [PSBTOutput(400, spend.script_pubkey)]
    raw = create_psbt(inputs, outputs, version=1, locktime=500_000)
    assert raw == create_psbt([replace(item, sequence=int(item.sequence)) for item in inputs],
                              outputs, version=1, locktime=500_000)
    tx = read_maps(raw)[0][b'\x00']
    assert tx[:5] == bytes.fromhex('0100000004')
    assert [int.from_bytes(tx[42 + 41 * i:46 + 41 * i], 'little') for i in range(4)] == sequences
    assert int.from_bytes(tx[-4:], 'little') == 500_000


@pytest.mark.parametrize('sequence', [-1, 2**32, True, False, 1.5, '4294967295'])
def test_invalid_sequences(spend, sequence):
    with pytest.raises(EncodingError, match='Sequence must be an integer'):
        create_psbt([PSBTInput(TXID, 0, 100, spend, sequence=sequence)],
                    [PSBTOutput(100, spend.script_pubkey)])


def test_unrelated_sequence_enum_is_rejected(spend):
    class OtherSequence(IntEnum):
        FINAL = 0xFFFFFFFF

    with pytest.raises(EncodingError, match='Sequence must be an integer'):
        create_psbt([PSBTInput(TXID, 0, 100, spend, sequence=OtherSequence.FINAL)],
                    [PSBTOutput(100, spend.script_pubkey)])


@pytest.mark.parametrize('field', ['amount', 'output_index'])
def test_sequence_presets_are_rejected_in_other_input_fields(spend, field):
    item = replace(PSBTInput(TXID, 0, 100, spend), **{field: InputSequence.FINAL})
    with pytest.raises(EncodingError, match='must be an integer'):
        create_psbt([item], [PSBTOutput(100, spend.script_pubkey)])


def test_sequence_presets_are_rejected_as_locktime(spend):
    with pytest.raises(EncodingError, match='Locktime must be an integer'):
        create_psbt([PSBTInput(TXID, 0, 100, spend)],
                    [PSBTOutput(100, spend.script_pubkey)], locktime=InputSequence.FINAL)


def test_op_return_alongside_payment_and_change(spend):
    change = derive_native_segwit([(ROOT, None)], 1, 3)
    data_script = op_return_script(bytes(range(80)))
    raw = create_psbt(
        [PSBTInput(TXID, 0, 100_000, spend)],
        [PSBTOutput(60_000, spend.script_pubkey),
         PSBTOutput(0, data_script),
         PSBTOutput(39_000, change.script_pubkey, change)],
    )
    global_map, source, payment, data, change_map = read_maps(raw)
    # One empty-script input occupies 41 bytes after version and input count.
    expected_outputs = b'\x03'
    for amount, script in ((60_000, spend.script_pubkey), (0, data_script),
                           (39_000, change.script_pubkey)):
        expected_outputs += amount.to_bytes(8, 'little') + bytes([len(script)]) + script
    assert global_map[b'\x00'][46:] == expected_outputs + b'\x00' * 4
    assert source[b'\x01'][:8] == (100_000).to_bytes(8, 'little')
    assert payment == data == {}
    pubkey, origin = change.derivations[0]
    assert change_map == {b'\x02' + pubkey: origin.serialize()}
    assert dust_threshold(data_script) == 0


def test_multisig_ordering_and_explicit_change():
    root = ExtendedKey.parse(ROOT)
    keys = [(root.child(i), KeyOrigin(root.fingerprint, (i,))) for i in (3, 1, 2)]
    spend = derive_native_segwit(keys, 0, 700, threshold=2)
    change = derive_native_segwit(keys, 1, 900, threshold=2)
    reversed_spend = derive_native_segwit(list(reversed(keys)), 0, 700, threshold=2)
    assert spend.script_pubkey == reversed_spend.script_pubkey
    assert spend.witness_script[0] == 0x52
    assert spend.witness_script[-2:] == b'\x53\xae'
    raw = create_psbt([PSBTInput(TXID, 0, 200_000, spend), PSBTInput(TXID, 1, 100_000, spend)],
                      [PSBTOutput(299_000, change.script_pubkey, change)])
    global_map, first, second, output = read_maps(raw)
    assert {k: v for k, v in first.items() if k != b'\x01'} == {k: v for k, v in second.items() if k != b'\x01'}
    assert first[b'\x05'] == spend.witness_script
    assert output[b'\x01'] == change.witness_script
    assert len([key for key in global_map if key[0] == 1]) == 3
    for pubkey, origin in change.derivations:
        assert output[b'\x02' + pubkey] == origin.serialize()
        assert origin.path[-2:] == (1, 900)


@pytest.mark.parametrize('amount', [0, 1, MAX_MONEY])
def test_zero_fee_and_exact_amounts(spend, amount):
    data = create_psbt([PSBTInput(TXID, 0, amount, spend)], [PSBTOutput(amount, spend.script_pubkey)])
    assert int.from_bytes(read_maps(data)[1][b'\x01'][:8], 'little') == amount


def test_compact_size_large_counts_and_witness_script(spend):
    root = ExtendedKey.parse(ROOT)
    multi = derive_native_segwit([(root.child(i), KeyOrigin(root.fingerprint, (i,))) for i in range(15)],
                                0, 0, threshold=15)
    raw = create_psbt([PSBTInput(TXID, i, 1, multi) for i in range(253)],
                      [PSBTOutput(1, spend.script_pubkey)] * 253)
    maps = read_maps(raw)
    assert len(maps) == 507
    assert maps[0][b'\x00'][4:7] == bytes.fromhex('fdfd00')
    assert maps[1][b'\x05'] == multi.witness_script


@pytest.mark.parametrize('values', [
    {'txid': 'z' * 64}, {'txid': 'a' * 63}, {'output_index': -1},
    {'output_index': 2**32}, {'amount': -1}, {'amount': MAX_MONEY + 1},
    {'amount': 1.5}, {'amount': True}, {'sequence': -1},
])
def test_invalid_inputs(spend, values):
    with pytest.raises(EncodingError):
        create_psbt([replace(PSBTInput(TXID, 0, 100, spend), **values)], [PSBTOutput(0, spend.script_pubkey)])


def test_totals_duplicates_and_missing_rows(spend):
    item = PSBTInput(TXID, 0, 100, spend)
    output = PSBTOutput(101, spend.script_pubkey)
    for inputs, outputs in [([item], [output]), ([item, item], [output]), ([], [output]), ([item], [])]:
        with pytest.raises(EncodingError):
            create_psbt(inputs, outputs)
    with pytest.raises(EncodingError, match='Total input'):
        create_psbt([replace(item, amount=MAX_MONEY), replace(item, output_index=1)],
                    [replace(output, amount=0)])


@pytest.mark.parametrize('path', ['m//1', 'm/1/', '', 'm/-1', 'm/2147483648', 'm/1.0'])
def test_invalid_origin_paths(path):
    with pytest.raises(EncodingError):
        KeyOrigin.parse('deadbeef', path)


def test_hardened_origin_and_depth():
    origin = KeyOrigin.parse('DEADBEEF', "m/84'/0h/0H")
    assert origin.serialize().hex() == 'deadbeef540000800000008000000080'
    root = ExtendedKey.parse(ROOT)
    for key, invalid in [(root.child(1), None), (root.child(1), origin),
                         (root.child(1), KeyOrigin(root.fingerprint, (2,))), (root, origin)]:
        with pytest.raises(EncodingError):
            derive_native_segwit([(key, invalid)], 0, 0)
    with pytest.raises(EncodingError, match='Duplicate'):
        derive_native_segwit([(root, None), (root, None)], 0, 0)


def test_mismatched_scripts_and_origins(spend):
    with pytest.raises(EncodingError, match='does not match'):
        create_psbt([PSBTInput(TXID, 0, 1, spend)], [PSBTOutput(1, b'\x51', spend)])
    with pytest.raises(EncodingError, match='does not match'):
        create_psbt([PSBTInput(TXID, 0, 1, replace(spend, script_pubkey=b'\x51'))],
                    [PSBTOutput(1, b'\x51')])
    conflicting = replace(spend, xpubs=((spend.xpubs[0][0], KeyOrigin(b'\x00' * 4)),))
    with pytest.raises(EncodingError, match='Conflicting'):
        create_psbt([PSBTInput(TXID, 0, 1, spend)], [PSBTOutput(1, spend.script_pubkey, conflicting)])


@pytest.fixture(scope='module')
def core(tmp_path_factory):
    """Optional isolated node: no existing config, wallet, chain, or peers."""
    bitcoind = shutil.which('bitcoind')
    cli = shutil.which('bitcoin-cli')
    if not bitcoind or not cli:
        pytest.skip('Bitcoin Core binaries are not installed')
    directory = tmp_path_factory.mktemp('psbt-core')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    options = [f'-datadir={directory}', '-regtest', f'-rpcport={port}', '-conf=bitcoin.conf']
    (directory / 'bitcoin.conf').write_text('')
    log = (directory / 'process.log').open('w')
    process = subprocess.Popen([bitcoind, *options, '-server=1', '-listen=0', '-connect=0',
                                '-dnsseed=0', '-discover=0', '-listenonion=0', '-daemon=0',
                                '-printtoconsole=0'], stdout=log, stderr=log)

    def rpc(method, *args):
        result = subprocess.run([cli, *options, '-rpcwait', '-rpcwaittimeout=20', method,
                                 *(arg if isinstance(arg, str) else json.dumps(arg) for arg in args)],
                                text=True, capture_output=True, timeout=25)
        assert result.returncode == 0, result.stderr + (directory / 'process.log').read_text()
        return json.loads(result.stdout, parse_float=Decimal)

    try:
        rpc('getblockchaininfo')
        yield rpc
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()


@pytest.mark.parametrize('count,threshold', [(1, 1), (3, 2)])
def test_bitcoin_core_decodes_psbt(core, count, threshold):
    root = ExtendedKey.parse(ROOT)
    keys = [(root.child(i), KeyOrigin(root.fingerprint, (i,))) for i in range(count)]
    spend = derive_native_segwit(keys, 0, 500, threshold=threshold)
    change = derive_native_segwit(keys, 1, 900, threshold=threshold)
    raw = create_psbt([PSBTInput(TXID, 7, 123456789, spend)],
                      [PSBTOutput(123450000, change.script_pubkey, change)])
    decoded = core('decodepsbt', base64.b64encode(raw).decode())
    assert decoded['tx']['vin'][0]['txid'] == TXID
    assert decoded['tx']['vin'][0]['vout'] == 7
    assert decoded['tx']['vin'][0]['sequence'] == 0xFFFFFFFF
    assert decoded['inputs'][0]['witness_utxo']['amount'] == Decimal('1.23456789')
    assert decoded['fee'] == Decimal('0.00006789')
    assert decoded['inputs'][0]['sighash'] == 'ALL'
    assert len(decoded['global_xpubs']) == count
    assert len(decoded['inputs'][0]['bip32_derivs']) == count
    assert len(decoded['outputs'][0]['bip32_derivs']) == count
    if count > 1:
        assert decoded['inputs'][0]['witness_script']['hex'] == spend.witness_script.hex()
    fixture = json.loads((Path(__file__).parent / 'vectors' / 'psbt.json').read_text())
    reference = core('decodepsbt', fixture['base64'])
    assert reference['fee'] == Decimal('0.00006789')
    assert reference['tx']['vin'][0]['txid'] == TXID


def test_frozen_core_reference(spend):
    """Fixture independently decoded by Core; includes exact serialized maps."""
    fixture = json.loads((Path(__file__).parent / 'vectors' / 'psbt.json').read_text())
    raw = create_psbt([PSBTInput(TXID, 7, 123456789, spend)],
                      [PSBTOutput(123450000, spend.script_pubkey, spend)])
    assert base64.b64encode(raw).decode() == fixture['base64']


def test_upstream_bitcoin_core_creator_vector(spend):
    fixture = json.loads((Path(__file__).parent / 'vectors' / 'psbt_core_creator.json').read_text(), parse_float=Decimal)
    for case in fixture['creator']:
        # Arbitrary declared input metadata intentionally does not influence
        # the unsigned transaction in Core's creator-role reference vector.
        inputs = [PSBTInput(row['txid'], row['vout'], 200_000_000, spend) for row in case['inputs']]
        outputs = [PSBTOutput(int(amount * 100_000_000), address_to_script(address))
                   for row in case['outputs'] for address, amount in row.items()]
        raw = create_psbt(inputs, outputs)
        assert read_maps(raw)[0][b'\x00'] == read_maps(base64.b64decode(case['result']))[0][b'\x00']


@pytest.mark.parametrize('branch,index,address,pubkey,_wif', BIP84_ADDRESSES)
def test_bip84_signing_origins(branch, index, address, pubkey, _wif):
    spend = derive_native_segwit([(BIP84_ACCOUNT, BIP84_ORIGIN)], branch, index)
    assert spend.address == address
    assert spend.derivations[0][0].hex() == pubkey
    raw = create_psbt([PSBTInput(TXID, 0, 1000, spend)], [PSBTOutput(1000, spend.script_pubkey, spend)])
    maps = read_maps(raw)
    origin_bytes = (bytes.fromhex('73c5da0a540000800000008000000080')
                    + branch.to_bytes(4, 'little') + index.to_bytes(4, 'little'))
    assert maps[1][b'\x06' + bytes.fromhex(pubkey)] == origin_bytes
    assert maps[2][b'\x02' + bytes.fromhex(pubkey)] == origin_bytes
    xpub_entries = [key for key in maps[0] if key[0] == 1]
    assert xpub_entries[0][1:5] == bytes.fromhex('0488b21e')  # canonical xpub, not zpub


@pytest.mark.parametrize('count', [1, 3])
def test_core_signs_and_finalizes_public_test_vectors(core, count):
    sources = [derive_native_segwit([(BIP84_ACCOUNT, BIP84_ORIGIN)], branch, index)
               for branch, index, *_ in BIP84_ADDRESSES[:count]]
    # Only published BIP84 fixture keys, converted to regtest WIF encoding.
    wifs = [base58check_encode(b'\xef' + base58check_decode(row[4])[1:]) for row in BIP84_ADDRESSES[:count]]
    if count == 1:
        source = sources[0]
        descriptor = f'wpkh({wifs[0]})'
    else:
        derivations = tuple(sorted((item.derivations[0] for item in sources), key=lambda item: item[0]))
        witness = p2ms_script(2, [pk for pk, _ in derivations])
        source = SegwitSpend(address_from_script(witness, 'p2wsh'), p2wsh_script(witness),
                             derivations, sources[0].xpubs, witness)
        descriptor = f'wsh(sortedmulti(2,{",".join(wifs)}))'
    descriptor += '#' + descriptor_checksum(descriptor)
    raw = create_psbt([PSBTInput(TXID, 0, 100_000, source)], [PSBTOutput(99_000, sources[0].script_pubkey)])
    processed = core('descriptorprocesspsbt', base64.b64encode(raw).decode(), [descriptor])
    assert processed['complete'] is True
    finalized = core('decoderawtransaction', processed['hex'])
    witness_stack = finalized['vin'][0]['txinwitness']
    assert len(witness_stack) == (2 if count == 1 else 4)
    assert witness_stack[-1] == (sources[0].derivations[0][0].hex() if count == 1 else source.witness_script.hex())
    # Signing the fixture is local; deliberately never broadcast it.


def test_duplicate_outpoints_are_case_insensitive(spend):
    inputs = [PSBTInput('ab' * 32, 3, 100, spend), PSBTInput('AB' * 32, 3, 100, spend)]
    with pytest.raises(EncodingError, match='Duplicate input'):
        create_psbt(inputs, [PSBTOutput(100, spend.script_pubkey)])


def test_uint32_limits_and_nondefault_transaction_parameters(spend):
    raw = create_psbt([PSBTInput(TXID, 0xFFFFFFFF, 100, spend, sequence=0xFFFFFFFD)],
                      [PSBTOutput(100, spend.script_pubkey)], version=1, locktime=0xFFFFFFFF)
    tx = read_maps(raw)[0][b'\x00']
    assert tx[:4] == b'\x01\x00\x00\x00'
    assert tx[37:46] == bytes.fromhex('ffffffff00fdffffff')
    assert tx[-4:] == b'\xff' * 4


@pytest.mark.parametrize('amount', [-1, MAX_MONEY + 1, True, 0.5])
def test_invalid_output_amounts(spend, amount):
    with pytest.raises(EncodingError, match='Amount in satoshis'):
        create_psbt([PSBTInput(TXID, 0, 100, spend)], [PSBTOutput(amount, spend.script_pubkey)])


def test_depth_one_master_fingerprint_must_match_parent():
    root = ExtendedKey.parse(ROOT)
    with pytest.raises(EncodingError, match='depth-one'):
        derive_native_segwit([(root.child(1), KeyOrigin(b'\x00' * 4, (1,)))], 0, 0)


@pytest.mark.parametrize('pubkey', [b'\x04' + b'\x11' * 64, b'\x02' + b'\xff' * 32, b'\x02' * 32])
def test_invalid_signing_public_keys_are_rejected(spend, pubkey):
    source = replace(spend, script_pubkey=p2wpkh_script(pubkey),
                     derivations=((pubkey, spend.derivations[0][1]),))
    with pytest.raises(EncodingError, match='public key'):
        create_psbt([PSBTInput(TXID, 0, 100, source)], [PSBTOutput(100, spend.script_pubkey)])


# Core GetDustThreshold reference values at 3000 sat/kvB:
# https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.cpp
@pytest.mark.parametrize('script,expected', [
    ('76a914' + '11' * 20 + '88ac', 546),  # P2PKH
    ('a914' + '11' * 20 + '87', 540),      # P2SH
    ('0014' + '11' * 20, 294),            # P2WPKH
    ('0020' + '11' * 32, 330),            # P2WSH
    ('5120' + '11' * 32, 330),            # P2TR
    ('6a', 0),                            # OP_RETURN
])
def test_dust_policy_vectors(script, expected):
    assert dust_threshold(bytes.fromhex(script)) == expected


def test_dust_policy_rate_and_script_boundaries():
    script = bytes.fromhex('0014' + '11' * 20)
    assert dust_threshold(script, dust_relay_fee=0) == 0
    assert dust_threshold(script, dust_relay_fee=1) == 1
    assert dust_threshold(script, dust_relay_fee=1000) == 98
    assert dust_threshold(b'\x51' * 10_001) == 0
    with pytest.raises(EncodingError):
        dust_threshold(script, dust_relay_fee=-1)


@pytest.mark.parametrize('rate,expected', [(1001, 99), (3001, 295)])
def test_dust_policy_rounds_up_fractional_satoshis(rate, expected):
    # Core v29 CFeeRate::GetFee uses ceil; v30 uses EvaluateFeeUp.
    # https://github.com/bitcoin/bitcoin/blob/v29.0/src/policy/feerate.cpp
    script = bytes.fromhex('0014' + '11' * 20)
    assert dust_threshold(script, dust_relay_fee=rate) == expected


@pytest.mark.parametrize('output_metadata', [False, True])
@pytest.mark.parametrize('mutation', [
    'private_mainnet', 'private_testnet', 'private_key_data', 'off_curve',
    'version', 'uncompressed', 'length', 'depth', 'bytearray',
])
def test_invalid_global_xpubs_are_rejected_without_btclib(spend, mutation, output_metadata):
    raw, origin = spend.xpubs[0]
    if mutation in ('private_mainnet', 'private_testnet', 'private_key_data'):
        # Deterministic dummy scalar; never real signing material. The third
        # case disguises private key data behind a public version prefix.
        version = {'private_mainnet': bytes.fromhex('0488ade4'),
                   'private_testnet': bytes.fromhex('04358394'),
                   'private_key_data': raw[:4]}[mutation]
        raw = version + raw[4:45] + b'\x00' + (1).to_bytes(32, 'big')
    elif mutation == 'off_curve':
        raw = raw[:45] + b'\x02' + b'\xff' * 32
    elif mutation == 'version':
        raw = b'\xff' * 4 + raw[4:]
    elif mutation == 'uncompressed':
        raw = raw[:45] + b'\x04' + raw[46:]
    elif mutation == 'length':
        raw = raw[:-1]
    elif mutation == 'depth':
        raw = raw[:4] + b'\x01' + raw[5:]
    elif mutation == 'bytearray':
        raw = bytearray(raw)
    malformed = replace(spend, xpubs=((raw, origin),))
    source = spend if output_metadata else malformed
    destination = malformed if output_metadata else None
    with pytest.raises(EncodingError):
        create_psbt([PSBTInput(TXID, 0, 100, source)],
                    [PSBTOutput(99, spend.script_pubkey, destination)])
