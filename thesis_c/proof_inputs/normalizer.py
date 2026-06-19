from __future__ import annotations

from .schema import ProofPayload

BN254_FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

# First-pass bounded shape from current sample data.
MAX_ACCOUNT_PROOF_NODES = 4
MAX_ACCOUNT_NODE_BYTES = 544
ACCOUNT_PATH_NIBBLES = 64
MAX_LEAF_PATH_NIBBLES = 64


def normalize_hex(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("0x"):
        return "0x" + text[2:]
    return "0x" + text


def hex_to_bytes(value: str) -> bytes:
    text = normalize_hex(value)[2:]
    if len(text) % 2 == 1:
        text = "0" + text
    return bytes.fromhex(text)


def bytes_to_hex(value: bytes) -> str:
    return "0x" + value.hex()


def bytes_to_u8_list(value: bytes) -> list[int]:
    return [int(b) for b in value]


def hex_to_u8_list(value: str) -> list[int]:
    return bytes_to_u8_list(hex_to_bytes(value))


def pad_u8_list(value: list[int], length: int) -> list[int]:
    if len(value) > length:
        raise ValueError(f"List length {len(value)} exceeds bound {length}")
    return value + [0] * (length - len(value))


def pad_nested_u8_lists(values: list[list[int]], outer: int, inner: int) -> list[list[int]]:
    if len(values) > outer:
        raise ValueError(f"Nested outer length {len(values)} exceeds bound {outer}")
    padded = [pad_u8_list(value, inner) for value in values]
    while len(padded) < outer:
        padded.append([0] * inner)
    return padded


def pad_field_list(values: list[int], length: int) -> list[int]:
    if len(values) > length:
        raise ValueError(f"Field list length {len(values)} exceeds bound {length}")
    return values + [0] * (length - len(values))


def to_field(value: int | str | bytes) -> int:
    if isinstance(value, int):
        return value % BN254_FIELD_MODULUS
    if isinstance(value, bytes):
        return int.from_bytes(value, "big") % BN254_FIELD_MODULUS
    text = value.strip().lower()
    if text.startswith("0x"):
        return int(text[2:] or "0", 16) % BN254_FIELD_MODULUS
    if text.isdigit():
        return int(text) % BN254_FIELD_MODULUS
    return int.from_bytes(text.encode("utf-8"), "big") % BN254_FIELD_MODULUS


def compute_leaf_value_commitment(
    nonce: int, balance: int, storage_root: bytes, code_hash: bytes
) -> int:
    """
    Deterministic account commitment mirrored by `types.nr::compute_leaf_fields_commitment`.
    This value is used as a public leaf-value commitment anchor for partial in-circuit binding.
    """
    acc = to_field(nonce + balance * 17)
    for byte in storage_root:
        acc = to_field(acc * 257 + byte)
    for byte in code_hash:
        acc = to_field(acc * 263 + byte)
    return acc


def compute_leaf_fields_commitment(
    nonce: int, balance: int, storage_root: bytes, code_hash: bytes
) -> int:
    """
    Backward-compatible alias for `compute_leaf_value_commitment`.
    """
    return compute_leaf_value_commitment(nonce, balance, storage_root, code_hash)


def account_proof_node_count(payload: ProofPayload) -> int:
    return len(payload.account_proof)


def storage_proof_node_count(payload: ProofPayload) -> int:
    return sum(len(entry.proof) for entry in payload.storage_proof)


def raw_proof_byte_size(payload: ProofPayload) -> int:
    total = 0
    for node_hex in payload.account_proof:
        total += len(hex_to_bytes(node_hex))
    for entry in payload.storage_proof:
        for node_hex in entry.proof:
            total += len(hex_to_bytes(node_hex))
    return total
