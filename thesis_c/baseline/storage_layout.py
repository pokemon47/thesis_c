"""Canonical layout checks for the first storage-proof milestone."""

from __future__ import annotations

from dataclasses import dataclass

import rlp

from thesis_c.baseline.account_layout import (
    RlpItemLayout,
    assert_canonical_uint_rlp_item,
    encoded_slice,
    parse_rlp_item,
)
from thesis_c.baseline.verifier_adapter import decode_compact_with_flags
from thesis_c.hashes.base import HashVariant
from thesis_c.proof_inputs.normalizer import hex_to_bytes


@dataclass(frozen=True, slots=True)
class StorageLeafLayout:
    leaf_node: bytes
    leaf_node_len: int
    outer_list: RlpItemLayout
    compact_path_item: RlpItemLayout
    value_item: RlpItemLayout
    value_payload_offset: int
    value_payload_len: int
    active_value_bytes: bytes
    active_value_len: int
    decoded_value: int
    path_nibbles: tuple[int, ...]


def parse_one_node_storage_leaf(
    node_rlp: bytes,
    *,
    expected_path: list[int] | tuple[int, ...],
    storage_root: bytes,
    hash_variant: HashVariant,
) -> StorageLeafLayout:
    """Validate and describe a one-node terminal storage proof."""
    if hash_variant.digest(node_rlp) != storage_root:
        raise ValueError("storage_root_node_hash_mismatch")

    try:
        decoded = rlp.decode(node_rlp)
    except Exception as exc:
        raise ValueError(f"storage_leaf_rlp_decode_error:{exc}") from exc
    if not isinstance(decoded, list) or len(decoded) != 2:
        raise ValueError("storage_proof_must_be_one_terminal_leaf")

    outer = parse_rlp_item(node_rlp, 0)
    if outer.prefix_form not in {"short_list", "long_list"}:
        raise ValueError("storage_leaf_outer_list_must_be_rlp_list")
    if outer.encoded_len != len(node_rlp):
        raise ValueError("storage_leaf_has_trailing_bytes")

    compact = parse_rlp_item(node_rlp, outer.payload_offset)
    value = parse_rlp_item(node_rlp, compact.encoded_offset + compact.encoded_len)
    if compact.prefix_form not in {"single", "short_string", "long_string"}:
        raise ValueError("storage_compact_path_must_be_bytes")
    if value.prefix_form not in {"single", "short_string"}:
        raise ValueError("storage_value_must_be_canonical_scalar_item")
    if value.encoded_offset + value.encoded_len != outer.payload_offset + outer.payload_len:
        raise ValueError("storage_leaf_must_contain_exactly_two_items")

    compact_path_bytes = node_rlp[
        compact.payload_offset : compact.payload_offset + compact.payload_len
    ]
    path_nibbles, is_leaf = decode_compact_with_flags(compact_path_bytes)
    if not is_leaf:
        raise ValueError("storage_proof_extension_not_supported")
    if tuple(path_nibbles) != tuple(expected_path):
        raise ValueError("storage_compact_path_mismatch")
    if len(path_nibbles) != 64:
        raise ValueError("storage_compact_path_must_consume_64_nibbles")

    value_bytes = encoded_slice(node_rlp, value)
    decoded_value = assert_canonical_uint_rlp_item(value_bytes)
    if decoded_value == 0:
        raise ValueError("storage_value_must_be_nonzero")
    active_value_bytes = node_rlp[
        value.payload_offset : value.payload_offset + value.payload_len
    ]
    if len(active_value_bytes) > 32:
        raise ValueError("storage_value_payload_exceeds_32_bytes")

    return StorageLeafLayout(
        leaf_node=node_rlp,
        leaf_node_len=len(node_rlp),
        outer_list=outer,
        compact_path_item=compact,
        value_item=value,
        value_payload_offset=value.payload_offset,
        value_payload_len=value.payload_len,
        active_value_bytes=bytes(active_value_bytes),
        active_value_len=len(active_value_bytes),
        decoded_value=decoded_value,
        path_nibbles=tuple(path_nibbles),
    )


def storage_slot_bytes(slot: str) -> bytes:
    raw = hex_to_bytes(slot)
    if len(raw) > 32:
        raise ValueError("storage_slot_exceeds_32_bytes")
    return raw.rjust(32, b"\x00")


def derive_storage_trie_key(slot: str, hash_variant: HashVariant) -> bytes:
    return hash_variant.digest(storage_slot_bytes(slot))
