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
# BIP49 account 0 ypub (same mnemonic).
YPUB = ("ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7"
        "icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP")

# BIP84's other published public fixture: the root zpub, at depth zero.
# https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki#test-vectors
BIP84_ROOT_ZPUB = (
    "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEe"
    "ZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF"
)

# BIP32's published xpub fixtures. Vectors 3 and 4 specifically cover leading
# zero serialization cases. The zpub/Zpub values below replace only the four
# SLIP-0132 version bytes, then Base58Check-encode the official BIP32 payload.
# https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vectors
CONVERSION_VECTORS = [
    (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjq"
        "JoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        "zpub6jftahH18ngZxUuv6oSniLNrBCSSE1B4EEU59bwTCEt8x6aS6b2mdfLxbS4QS53g8"
        "5SWWP6wexqeer516433gYpZQoJie2tcMYdJ1SYYYAL",
        "Zpub6vZyhw1ShkEwP45J3TumYQietzUhSMreYW7k4sCza1iYaH9LrzR3inCtQ91szWGa"
        "MYWVNy74YBE9n1gmPHBzq2wEFGR83SMcFGuAbGkfiwg",
    ),
    (
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK"
        "1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        "zpub6mwJaQaUE3oZ763dJZKRbNUxW1znc5f4uqty7hKaAS5RKNscWpZrkohNNhd7BNxD"
        "8Hj5NceNPbujdF3935mRkSHHcS6yZLnpsUkrK1XoMLr",
        "Zpub6xqPheJuo1MvXfD1FDnQRSpmDp33pSLfE7Ye2xb7YCupwZSXHDx8qvZJBQaajpB7"
        "Mko4FCeVGpJEkQeuLJvNtvPxSuDNxkFpmD2itxTfBFT",
    ),
    (
        "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gS"
        "PSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
        "zpub6jftahH18ngZw9sQjM1sNXMeJ2uxfVb9dA2MqqhqSK5oDKptvt3g1pk5RXgMxuzH"
        "CiSAF3e7SiAkowS93wzeEoUePyQQD5q7Tdp6ooFXLSf",
        "Zpub6vZyhw1ShkEwMj2ng1UrCbhT1pxDsrGjwRg2m6yNp5vCqWPohHRx6wc1EEdqXMDB"
        "SBW97deEKvZFw73uMB9bPHbKESWocVJ7MN5yPmuMFYN",
    ),
    (
        "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBa"
        "ohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        "zpub6n36Kf78pA3v8gxoxVMNRn7JzPXLpM142eGJf5PgNd1AULxMWNpY6HXnjFWshGb2Q"
        "5w121PrHfNFSQNUzBvpp3kb55MHkwKuwpB1UETtD11",
        "Zpub6xwBStqaP7cHZG8Bu9pMFrT7iBZc2hgeLuuyaLfDkPqa6XXGGnCpBQPiXxUMFhovd"
        "YzytbPyAskkZZzFHR5mxXsFuYThALnuqYSt49f87xb",
    ),
    (
        "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVx"
        "yL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
        "zpub6jftahH18ngZyDNya5NgBGpXvGW8ajztsHimDaPRJqvV4DeE8neSE3JB7ew2zMaLn"
        "FZiPisJPUwVcpDGUA1ZKfLZAPhUmPnvNEVKtZUGaJQ",
        "Zpub6vZyhw1ShkEwPnYMWjqf1MALe4YPo6gVBZNS8qexgcktgQD8uC2iKAA6vMtWYnoF"
        "1idhGJsRGhKzjyq2mPAWU9TDzrotAoFvFxmCUa8Pe4d",
    ),
    (
        "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP"
        "56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
        "zpub6npzy5PfWYo1c6Q7CQJTBfvJNCPQJ3XScbLRZYZPxHzTYkhLh85AN5yXHFCo1ywUC"
        "ML5LmFuzQsk9juLAwTxQyPbCi8SeCtJR33Nh3P9PYj",
        "Zpub6yj66K875WMP2fZV94mS1kG75zRfWQD2vrz6UopwL4psAwGFTXTSTCqT5xAGaRANR"
        "pQ4DMG2sdGFGuX6UAcuZTWG3BEr3cMJJmKFGyNJWux",
    ),
]

# Public BIP84 testnet fixture from the bip84 reference implementation:
# https://github.com/Anderson-Juhasc/bip84
TESTNET_TPUB = (
    "tpubD9oHSJ9ANKEvRR1voAK8w57BbRnq13gJRnoDEYhAGawHMQ2o8SmQF7TPB8gr6uzBcij"
    "SawcRYGgK9CnEXXbrS4W236mrzsUtF91VTxrbkzv"
)
TESTNET_VPUB = (
    "vpub5Vm8JiyeMgCWT2SqgFkoJyaovNQH8RCF3wAUKCrFAfRdVujdYubBrYUGtggtabj71X"
    "xvUQuS5r9AgT4VhGvax9gXEpdi9XBg7jHnvm1WDii"
)
TESTNET_VPUB_MULTISIG = (
    "Vpub5gfDRxi5vdkssbcDcvDn93vceASYLmsqNCp9EU7nYSG386JYKJyTwfLChPeN92x1F"
    "12uLzuYy4XfocgFzW5Y6doC5Hk7Yveg1TZfWn2xWyi"
)


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
    acc = bw.Account(YPUB)
    assert acc.script_type == "p2sh-p2wpkh"
    assert acc.receive_address(0) == "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"


def test_bip32_vector1_public_derivation():
    parent = ExtendedKey.parse(
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhw"
        "BZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"
    )
    # Public derivation from M/0' to M/0'/1, from BIP32 test vector 1.
    node = parent.derive_path("1")
    assert node.pubkey.hex() == \
        "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c"
    assert node.serialize() == (
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMi"
        "Gj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    )
    assert node.fingerprint.hex() == "bef5a2f9"


def test_private_extended_key_is_rejected():
    private_key = (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKm"
        "PGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    with pytest.raises(bw.EncodingError, match="private extended keys"):
        ExtendedKey.parse(private_key)


def test_slip132_key_converts_to_canonical_xpub():
    key = ExtendedKey.parse(ZPUB)
    canonical = ExtendedKey.parse(key.to_xpub())
    assert canonical.version == 0x0488B21E
    assert canonical.pubkey == key.pubkey
    assert canonical.chain_code == key.chain_code


def test_slip132_key_converts_to_canonical_zpub():
    key = ExtendedKey.parse(ZPUB)
    canonical = ExtendedKey.parse(key.to_xpub())
    zpub_key = ExtendedKey.parse(canonical.to_zpub())
    assert zpub_key.version == 0x04B24746
    assert zpub_key.pubkey == key.pubkey
    assert zpub_key.chain_code == key.chain_code
    assert zpub_key.serialize() == ZPUB


def test_slip132_key_converts_to_canonical_Zpub():
    key = ExtendedKey.parse(ZPUB)
    canonical = ExtendedKey.parse(key.to_xpub())
    Zpub_key = ExtendedKey.parse(canonical.to_Zpub())
    assert Zpub_key.version == 0x02AA7ED3
    assert Zpub_key.pubkey == key.pubkey
    assert Zpub_key.chain_code == key.chain_code
    assert ExtendedKey.parse(Zpub_key.to_xpub()).serialize() == canonical.serialize()
    assert ExtendedKey.parse(Zpub_key.to_zpub()).serialize() == ZPUB


def test_bip84_root_conversion_vector():
    """The official BIP84 root fixture preserves the zero-depth fields."""
    key = ExtendedKey.parse(BIP84_ROOT_ZPUB)
    assert key.depth == 0
    assert key.parent_fingerprint == b"\0" * 4
    assert key.child_number == 0
    assert key.to_xpub() == (
        "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLi"
        "TVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8"
    )


@pytest.mark.parametrize("xpub,zpub,Zpub", CONVERSION_VECTORS)
def test_bip32_public_vectors_convert_to_slip132(xpub, zpub, Zpub):
    """Conversion changes exactly the version bytes of official BIP32 vectors."""
    source = ExtendedKey.parse(xpub)
    native = ExtendedKey.parse(source.to_zpub())
    multisig = ExtendedKey.parse(source.to_Zpub())

    assert source.to_zpub() == zpub
    assert source.to_Zpub() == Zpub
    for converted in (native, multisig):
        assert converted.depth == source.depth
        assert converted.parent_fingerprint == source.parent_fingerprint
        assert converted.child_number == source.child_number
        assert converted.chain_code == source.chain_code
        assert converted.pubkey == source.pubkey


def test_testnet_conversion_vectors():
    """Testnet conversions must choose vpub/Vpub, never mainnet variants."""
    source = ExtendedKey.parse(TESTNET_TPUB)
    assert source.to_zpub() == TESTNET_VPUB
    assert source.to_Zpub() == TESTNET_VPUB_MULTISIG
    assert ExtendedKey.parse(TESTNET_VPUB).to_xpub() == TESTNET_TPUB
    assert ExtendedKey.parse(TESTNET_VPUB_MULTISIG).to_xpub() == TESTNET_TPUB


@pytest.mark.parametrize("source", [YPUB, ZPUB])
def test_mainnet_single_sig_prefixes_normalize_and_reencode(source):
    """ypub and zpub payloads are interchangeable conversion inputs."""
    key = ExtendedKey.parse(source)
    canonical = key.to_xpub()
    assert ExtendedKey.parse(canonical).to_zpub() == key.to_zpub()
    assert ExtendedKey.parse(canonical).to_Zpub() == key.to_Zpub()


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


def test_wrapped_multisig_matches_reference_vector():
    xpubs = [
        ("xpub68w2bYfTxScnfFfGvUTGnEEpRyagyBSQfAHtyxi9ncSncYR38QMXeGNEqYFWwaDV"
         "F1ybX7fRK7obyWDxtDoX3f86dCDdVFW6Qoge2ZR6y9J"),
        ("xpub68w2bYfTxScniKLPJv7uDCo1wNDkadKZd5p4N4YU1jTqDALA65z6eN4MhbmkZAuA"
         "wW5U2Yj4ph2hfFuBQbEtYySeuDep2uD892umxEdzjMT"),
    ]
    account = bw.MultisigAccount(xpubs, 2, "p2sh-p2wsh")
    assert account.receive_address(0) == "3Bke1vqUtyAcZb6yJkMTKrU6AckyJYd8m2"
