from __future__ import annotations

import rlp

from thesis_c.proof_inputs.schema import StorageProofEntry


def hex_quantity_to_int(value: str) -> int:
    text = value.strip().lower()
    if not text:
        raise ValueError("Storage quantity cannot be empty.")
    if text.startswith("0x"):
        return int(text[2:] or "0", 16)
    return int(text, 10)


def int_to_hex_quantity(value: int) -> str:
    if value < 0:
        raise ValueError("Storage quantity cannot be negative.")
    return hex(value)


def decode_storage_leaf_value_int(value_rlp: bytes) -> int:
    decoded = rlp.decode(value_rlp)
    if not isinstance(decoded, (bytes, bytearray)):
        raise ValueError("Storage leaf value is not an RLP bytes scalar.")
    value_bytes = bytes(decoded)
    if not value_bytes:
        return 0
    return int.from_bytes(value_bytes, "big")


def decode_storage_entry(entry: StorageProofEntry) -> dict[str, int | str]:
    value_int = hex_quantity_to_int(entry.value)
    return {
        "key": entry.key,
        "value_hex": int_to_hex_quantity(value_int),
        "value_int": value_int,
        "proof_nodes": len(entry.proof),
    }
