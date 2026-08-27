"""BIP32/44/49/84/86 derivation against the official test vectors."""

import pytest

import bitwalkit as bw
from bitwalkit.bip32 import ExtendedKey
from bitwalkit.errors import DerivationError

# BIP84 account 0 zpub (mnemonic abandon...about).
ZPUB = ("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADq"
        "tfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
# BIP86 account 0 xpub (same mnemonic).
XPUB86 = ("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky"
          "7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")
# BIP49 account 0 yprv (same mnemonic).
YPRV = ("yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY7"
        "9hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF")


def test_bip84_receive_addresses():
    acc = bw.Account(ZPUB)
    assert acc.script_type == "p2wpkh"
    assert acc.receive_address(0) == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    assert acc.receive_address(1) == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
    assert acc.change_address(0) == "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"


def test_bip86_taproot_addresses():
    acc = bw.Account(XPUB86, script_type="p2tr")
    assert acc.receive_address(0) == \
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
    assert acc.receive_address(1) == \
        "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
    assert acc.change_address(0) == \
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7"


def test_bip49_p2sh_wrapped_segwit():
    acc = bw.Account(YPRV)
    assert acc.script_type == "p2sh-p2wpkh"
    assert acc.receive_address(0) == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"


def test_bip32_vector1_fingerprint_and_chain():
    m = ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKm"
         "PGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    root = ExtendedKey.parse(m)
    assert root.fingerprint.hex() == "3442193e"
    # m/0'/1 public key (BIP32 test vector 1).
    node = root.derive_path("0'/1")
    assert node.pubkey.hex() == \
        "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"


def test_neuter_matches_known_xpub():
    # BIP32 test vector 1: neutering m/0' (xprv) must reproduce the published xpub.
    m = ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKm"
         "PGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
    expected = ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhw"
                "BZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")
    node = ExtendedKey.parse(m).derive_path("0'")
    assert node.neuter().serialize() == expected


def test_slip132_key_converts_to_canonical_xpub():
    key = ExtendedKey.parse(ZPUB)
    canonical = ExtendedKey.parse(key.to_xpub())
    assert canonical.version == 0x0488B21E
    assert canonical.pubkey == key.pubkey
    assert canonical.chain_code == key.chain_code


def test_path_accepts_string_components():
    key = ExtendedKey.parse(ZPUB)
    assert key.derive_path(("0", "5")) == key.derive_path("0/5")


def test_hardened_from_pubkey_rejected():
    acc = ExtendedKey.parse(ZPUB)
    with pytest.raises(DerivationError):
        acc.derive_path("0'")


@pytest.mark.parametrize("path", ["-1", "x", "0//x", "2147483648"])
def test_invalid_derivation_paths_are_rejected(path):
    with pytest.raises(DerivationError):
        ExtendedKey.parse(ZPUB).derive_path(path)


def test_multisig_is_bip67_sorted_and_stable():
    xpubs = [
        ("xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6"
         "ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"),
        XPUB86,
    ]
    a = bw.MultisigAccount(xpubs, m=2, script_type="p2wsh")
    b = bw.MultisigAccount(list(reversed(xpubs)), m=2, script_type="p2wsh")
    # BIP67 sorting => cosigner order does not change the address.
    assert a.receive_address(0) == b.receive_address(0)
    assert a.receive_address(0).startswith("bc1q")


def test_wrapped_multisig_matches_btclib_vector():
    xpubs = [
        ("xpub68w2bYfTxScnfFfGvUTGnEEpRyagyBSQfAHtyxi9ncSncYR38QMXeGNEqYFWwaDV"
         "F1ybX7fRK7obyWDxtDoX3f86dCDdVFW6Qoge2ZR6y9J"),
        ("xpub68w2bYfTxScniKLPJv7uDCo1wNDkadKZd5p4N4YU1jTqDALA65z6eN4MhbmkZAuA"
         "wW5U2Yj4ph2hfFuBQbEtYySeuDep2uD892umxEdzjMT"),
    ]
    account = bw.MultisigAccount(xpubs, 2, "p2sh-p2wsh")
    assert account.receive_address(0) == "3Bke1vqUtyAcZb6yJkMTKrU6AckyJYd8m2"
