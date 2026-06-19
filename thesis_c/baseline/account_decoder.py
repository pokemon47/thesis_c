from __future__ import annotations

import rlp

from thesis_c.proof_inputs.schema import AccountLeaf


def _int_from_rlp_bytes(value: bytes) -> int:
    if value in (b"", b"\x00"):
        return 0
    return int.from_bytes(value, "big")


def decode_account_leaf(leaf_rlp: bytes) -> AccountLeaf:
    decoded = rlp.decode(leaf_rlp)
    if not isinstance(decoded, list) or len(decoded) != 4:
        raise ValueError("Account leaf is not a 4-field RLP list.")

    nonce_raw, balance_raw, storage_root_raw, code_hash_raw = decoded
    if not all(isinstance(x, (bytes, bytearray)) for x in decoded):
        raise ValueError("Account leaf fields are not bytes.")

    return AccountLeaf(
        nonce=_int_from_rlp_bytes(bytes(nonce_raw)),
        balance=_int_from_rlp_bytes(bytes(balance_raw)),
        storage_root="0x" + bytes(storage_root_raw).hex(),
        code_hash="0x" + bytes(code_hash_raw).hex(),
        rlp_hex="0x" + leaf_rlp.hex(),
    )
