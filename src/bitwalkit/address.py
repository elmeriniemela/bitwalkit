"""Scripts, addresses, and Electrum scripthashes.

Builds a scriptPubKey and its address from a public key (or redeem/witness
script) for every address type the Odoo wallet uses -- P2PKH, P2SH-P2WPKH
(BIP49), P2WPKH, P2WSH, P2SH-P2WSH, and P2TR (BIP86) -- and decodes an
address back to its scriptPubKey. ``address_to_scripthash`` reproduces the
Electrum protocol scripthash (replacing the only bit of vendored Electrum the
Odoo code used).
"""

from __future__ import annotations

from ._secp import G, GE
from .encoding import base58check_decode, base58check_encode, bech32_decode, bech32_encode
from .errors import EncodingError
from .hashing import hash160, sha256, tagged_hash

__all__ = [
    "NETWORKS",
    "address_from_pubkey",
    "address_from_script",
    "address_to_script",
    "address_to_scripthash",
    "script_to_scripthash",
    "p2pkh_script",
    "p2sh_script",
    "p2wpkh_script",
    "p2wsh_script",
    "p2tr_script",
    "p2ms_script",
    "p2pk_script",
]

# Base58 version bytes and bech32 HRP per network.
NETWORKS: dict[str, dict] = {
    "mainnet": {"p2pkh": 0x00, "p2sh": 0x05, "hrp": "bc"},
    "testnet": {"p2pkh": 0x6F, "p2sh": 0xC4, "hrp": "tb"},
    "regtest": {"p2pkh": 0x6F, "p2sh": 0xC4, "hrp": "bcrt"},
}
_HRPS = {params["hrp"]: net for net, params in NETWORKS.items()}

# Opcodes.
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE
OP_0 = 0x00
OP_1 = 0x51  # OP_1..OP_16 are 0x51..0x60


def _pushdata(data: bytes) -> bytes:
    """Minimal push of ``data`` (adequate for keys/hashes, all < 76 bytes)."""
    if len(data) < 0x4C:
        return bytes([len(data)]) + data
    raise EncodingError("pushdata too large for this helper")


# --------------------------------------------------------------------------- #
# Raw scriptPubKey / script builders
# --------------------------------------------------------------------------- #

def p2pkh_script(pubkey: bytes) -> bytes:
    h = hash160(pubkey)
    return bytes([OP_DUP, OP_HASH160, len(h)]) + h + bytes([OP_EQUALVERIFY, OP_CHECKSIG])


def p2sh_script(script_hash: bytes) -> bytes:
    return bytes([OP_HASH160, len(script_hash)]) + script_hash + bytes([OP_EQUAL])


def p2wpkh_script(pubkey: bytes) -> bytes:
    h = hash160(pubkey)
    return bytes([OP_0, len(h)]) + h


def p2wsh_script(witness_script: bytes) -> bytes:
    h = sha256(witness_script)
    return bytes([OP_0, len(h)]) + h


def p2pk_script(pubkey: bytes) -> bytes:
    return _pushdata(pubkey) + bytes([OP_CHECKSIG])


def p2ms_script(m: int, pubkeys: list[bytes]) -> bytes:
    """Bare multisig script (used as the witness/redeem script for P2WSH/P2SH)."""
    n = len(pubkeys)
    if not (1 <= m <= n <= 16):
        raise EncodingError(f"invalid multisig m-of-n: {m}-of-{n}")
    body = b"".join(_pushdata(pk) for pk in pubkeys)
    return bytes([OP_1 - 1 + m]) + body + bytes([OP_1 - 1 + n, OP_CHECKMULTISIG])


def _taproot_output_key(internal_pubkey: bytes) -> bytes:
    """BIP86 output key: tweak the internal key with no script tree."""
    xonly = internal_pubkey[-32:] if len(internal_pubkey) in (32, 33) else internal_pubkey
    if len(xonly) != 32:
        raise EncodingError("invalid taproot internal key length")
    t = int.from_bytes(tagged_hash("TapTweak", xonly), "big")
    if t >= GE.ORDER:
        raise EncodingError("invalid taproot tweak")
    q = GE.lift_x(int.from_bytes(xonly, "big")) + (t * G)
    if q.infinity:
        raise EncodingError("taproot output key is infinity")
    return q.to_bytes_xonly()


def p2tr_script(internal_pubkey: bytes) -> bytes:
    program = _taproot_output_key(internal_pubkey)
    return bytes([OP_1, len(program)]) + program


# --------------------------------------------------------------------------- #
# Address encoding
# --------------------------------------------------------------------------- #

def _b58(version_byte: int, payload: bytes) -> str:
    return base58check_encode(bytes([version_byte]) + payload)


def address_from_pubkey(pubkey: bytes, script_type: str, network: str = "mainnet") -> str:
    """Address for a single public key under ``script_type``.

    ``script_type`` is one of p2pkh, p2sh-p2wpkh, p2wpkh, or p2tr.
    """
    params = NETWORKS[network]
    if script_type == "p2pkh":
        return _b58(params["p2pkh"], hash160(pubkey))
    if script_type == "p2wpkh":
        return bech32_encode(params["hrp"], 0, hash160(pubkey))
    if script_type == "p2sh-p2wpkh":
        redeem = p2wpkh_script(pubkey)  # 0x00 0x14 <hash160(pubkey)>
        return _b58(params["p2sh"], hash160(redeem))
    if script_type == "p2tr":
        return bech32_encode(params["hrp"], 1, _taproot_output_key(pubkey))
    raise EncodingError(f"unsupported single-key script type: {script_type}")


def address_from_script(witness_script: bytes, script_type: str, network: str = "mainnet") -> str:
    """Address wrapping a redeem/witness script (multisig): p2wsh or p2sh-p2wsh."""
    params = NETWORKS[network]
    if script_type == "p2wsh":
        return bech32_encode(params["hrp"], 0, sha256(witness_script))
    if script_type == "p2sh-p2wsh":
        redeem = p2wsh_script(witness_script)  # 0x00 0x20 <sha256(script)>
        return _b58(params["p2sh"], hash160(redeem))
    if script_type == "p2sh":
        return _b58(params["p2sh"], hash160(witness_script))
    raise EncodingError(f"unsupported script-wrapping type: {script_type}")


# --------------------------------------------------------------------------- #
# Address decoding + scripthash
# --------------------------------------------------------------------------- #

def address_to_script(address: str, network: str | None = None) -> bytes:
    """Decode an address into its scriptPubKey bytes."""
    lowered = address.lower()
    pos = lowered.rfind("1")
    hrp = lowered[:pos] if pos > 0 else None
    if hrp in _HRPS:
        if network is not None and _HRPS[hrp] != network:
            raise EncodingError(f"address is {_HRPS[hrp]}, expected {network}")
        _hrp, witver, program = bech32_decode(address)
        op = OP_0 if witver == 0 else (OP_1 - 1 + witver)
        return bytes([op, len(program)]) + program

    payload = base58check_decode(address)
    version, h = payload[0], payload[1:]
    for net, params in NETWORKS.items():
        if network is not None and net != network:
            continue
        if version == params["p2pkh"]:
            return bytes([OP_DUP, OP_HASH160, len(h)]) + h + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
        if version == params["p2sh"]:
            return p2sh_script(h)
    raise EncodingError(f"unrecognized address version byte {version:#04x}")


def script_to_scripthash(script: bytes) -> str:
    """Electrum protocol scripthash: ``sha256(scriptPubKey)`` reversed, hex."""
    return sha256(script)[::-1].hex()


def address_to_scripthash(address: str, network: str | None = None) -> str:
    """Electrum scripthash for an address (SHA256 of scriptPubKey, reversed)."""
    return script_to_scripthash(address_to_script(address, network))
