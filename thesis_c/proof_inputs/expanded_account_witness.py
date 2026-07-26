from __future__ import annotations

from dataclasses import asdict
from typing import Any

from thesis_c.baseline.account_layout import (
    encoded_slice,
    parse_nested_account_layout,
    parse_rlp_item,
    payload_slice,
)
from thesis_c.baseline.verifier_adapter import decode_compact_with_flags, hex_to_bytes
from thesis_c.proof_inputs.expanded_mpt_capacity import (
    ACCOUNT_PATH_NIBBLES,
    BRANCH_CHILD_SLOTS,
    MAX_EXTENSION_NODES,
    MAX_NODE_RLP_BYTES,
    MAX_PROOF_NODES,
    MAX_TERMINAL_VALUE_BYTES,
    MAX_TOTAL_PROOF_RLP_BYTES,
    WITNESS_VERSION,
)
from thesis_c.proof_inputs.normalizer import (
    pad_field_list,
    pad_nested_u8_lists,
    pad_u8_list,
)

BN254_FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)


def _layout4(layout: Any) -> list[int]:
    return [
        int(layout["encoded_offset"]),
        int(layout["encoded_len"]),
        int(layout["payload_offset"]),
        int(layout["payload_len"]),
    ]


def _zero_layouts(count: int, width: int = 4) -> list[list[int]]:
    return [[0] * width for _ in range(count)]


def _to_field(value: Any) -> int:
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return value % BN254_FIELD_MODULUS
    if isinstance(value, bytes):
        return int.from_bytes(value, "big") % BN254_FIELD_MODULUS
    if isinstance(value, str):
        text = value.strip().lower()
        if text.startswith("0x"):
            return int(text[2:] or "0", 16) % BN254_FIELD_MODULUS
        if text.isdigit():
            return int(text) % BN254_FIELD_MODULUS
        return int.from_bytes(text.encode("utf-8"), "big") % BN254_FIELD_MODULUS
    return int.from_bytes(str(value).encode("utf-8"), "big") % BN254_FIELD_MODULUS


def _parse_node(node_bytes: bytes) -> tuple[list[int], list[list[int]], int]:
    outer = parse_rlp_item(node_bytes, 0)
    if outer.encoded_len != len(node_bytes):
        raise ValueError("Node RLP has trailing bytes or an incorrect declared length.")
    if outer.prefix_form.endswith("_list") is False:
        raise ValueError("MPT node must decode to an RLP list.")

    items: list[list[int]] = []
    offset = outer.payload_offset
    end = outer.payload_offset + outer.payload_len
    while offset < end:
        item = parse_rlp_item(node_bytes, offset)
        items.append(_layout4(asdict(item)))
        offset = item.encoded_offset + item.encoded_len
    if offset != end:
        raise ValueError("MPT node item ranges do not match the declared payload.")

    if len(items) == 17:
        kind = 0
    elif len(items) == 2:
        compact_bytes = node_bytes[items[0][2] : items[0][2] + items[0][3]]
        _, is_leaf = decode_compact_with_flags(bytes(compact_bytes))
        kind = 2 if is_leaf else 1
    else:
        raise ValueError(f"Unsupported MPT node arity: {len(items)}")

    node_list_layout = _layout4(asdict(outer))
    if len(items) == 2:
        while len(items) < 17:
            items.append([0, 0, 0, 0])

    return node_list_layout, items, kind


def _child_ref_for_branch(
    node_bytes: bytes,
    node_items: list[list[int]],
    child_index: int,
) -> tuple[list[int], list[int], int]:
    selected = node_items[child_index]
    ref_len = selected[3]
    if ref_len == 0:
        raise ValueError("Selected branch child is empty.")
    if ref_len > 32:
        raise ValueError("Selected branch child exceeds 32 bytes.")
    ref_bytes = [0] * 32
    payload_offset = selected[2]
    for i in range(ref_len):
        ref_bytes[i] = node_bytes[payload_offset + i]
    ref_kind = 1 if ref_len < 32 else 2
    return selected, ref_bytes, ref_kind


def _child_ref_for_extension(
    node_bytes: bytes,
    node_items: list[list[int]],
) -> tuple[list[int], list[int], int]:
    selected = node_items[1]
    ref_len = selected[3]
    if ref_len == 0:
        raise ValueError("Selected extension child is empty.")
    if ref_len > 32:
        raise ValueError("Selected extension child exceeds 32 bytes.")
    ref_bytes = [0] * 32
    payload_offset = selected[2]
    for i in range(ref_len):
        ref_bytes[i] = node_bytes[payload_offset + i]
    ref_kind = 1 if ref_len < 32 else 2
    return selected, ref_bytes, ref_kind


def _derive_selected_ref(
    *,
    node_kind: int,
    node_bytes: bytes,
    node_items: list[list[int]],
    path_nibbles: list[int],
    cursor: int,
) -> tuple[list[int], list[int], int, int]:
    if node_kind == 0:
        child_index = path_nibbles[cursor]
        if child_index >= BRANCH_CHILD_SLOTS:
            raise ValueError("Invalid branch child index.")
        selected, ref_bytes, ref_kind = _child_ref_for_branch(
            node_bytes,
            node_items,
            child_index,
        )
        return selected, ref_bytes, ref_kind, cursor + 1

    if node_kind == 1:
        selected, ref_bytes, ref_kind = _child_ref_for_extension(node_bytes, node_items)
        compact_bytes = bytes(node_bytes[node_items[0][2] : node_items[0][2] + node_items[0][3]])
        path_nibbles_ext, is_leaf = decode_compact_with_flags(compact_bytes)
        if is_leaf:
            raise ValueError("Extension node compact path was marked as a leaf.")
        return selected, ref_bytes, ref_kind, cursor + len(path_nibbles_ext)

    return [0, 0, 0, 0], [0] * 32, 0, cursor


def build_keccak_account_inclusion_witness(
    public_inputs: dict[str, Any],
    private_inputs: dict[str, Any],
) -> dict[str, Any]:
    node_rlp_hexes = list(private_inputs["node_rlp_hexes"])
    node_rlp_bytes = [hex_to_bytes(str(item)) for item in node_rlp_hexes]
    active_count = int(private_inputs["account_proof_depth"])
    if active_count < 1 or active_count > MAX_PROOF_NODES:
        raise ValueError(
            f"Expanded account proof depth must be between 1 and {MAX_PROOF_NODES}, got {active_count}."
        )

    path_nibbles = [int(item) for item in list(private_inputs["path_nibbles"])]
    leaf_path_nibbles = [int(item) for item in list(private_inputs["leaf_path_nibbles"])]
    leaf_path_len = int(private_inputs["leaf_path_len"])

    node_list_layouts: list[list[int]] = []
    node_item_layouts: list[list[list[int]]] = []
    node_compact_layouts: list[list[int]] = []
    selected_ref_layouts: list[list[int]] = []
    selected_ref_bytes: list[list[int]] = []
    selected_ref_lengths: list[int] = []
    selected_ref_kinds: list[int] = []

    cursor = 0
    for index in range(active_count):
        node_bytes = node_rlp_bytes[index]
        node_list_layout, node_items, node_kind = _parse_node(node_bytes)
        node_list_layouts.append(node_list_layout)

        if len(node_items) == 17:
            pass
        else:
            # Already padded to 17 items by _parse_node.
            pass
        node_item_layouts.append(node_items)

        if node_kind == 0:
            node_compact_layouts.append([0, 0, 0, 0])
        else:
            node_compact_layouts.append(node_items[0])

        selected_layout, ref_bytes, ref_kind, cursor = _derive_selected_ref(
            node_kind=node_kind,
            node_bytes=node_bytes,
            node_items=node_items,
            path_nibbles=path_nibbles,
            cursor=cursor,
        )

        if index + 1 < active_count and node_kind in (0, 1):
            selected_ref_layouts.append(selected_layout)
            selected_ref_bytes.append(ref_bytes)
            selected_ref_lengths.append(selected_layout[3])
            selected_ref_kinds.append(ref_kind)
        else:
            selected_ref_layouts.append([0, 0, 0, 0])
            selected_ref_bytes.append([0] * 32)
            selected_ref_lengths.append(0)
            selected_ref_kinds.append(0)

    terminal_node = node_rlp_bytes[active_count - 1]
    terminal_kind = int(private_inputs["node_kinds"][active_count - 1])
    if terminal_kind == 0:
        terminal_layout = node_item_layouts[active_count - 1][16]
    elif terminal_kind == 2:
        terminal_layout = node_item_layouts[active_count - 1][1]
    else:
        raise ValueError(
            f"Unsupported terminal node kind for expanded account witness: {terminal_kind}"
        )
    terminal_value_len = int(terminal_layout[3])
    terminal_value = terminal_node[terminal_layout[2] : terminal_layout[2] + terminal_value_len]
    if terminal_value_len > MAX_TERMINAL_VALUE_BYTES:
        raise ValueError(
            f"Terminal account value length {terminal_value_len} exceeds {MAX_TERMINAL_VALUE_BYTES}."
        )

    padded_node_bytes = pad_nested_u8_lists(
        [list(node) for node in node_rlp_bytes],
        MAX_PROOF_NODES,
        MAX_NODE_RLP_BYTES,
    )
    padded_node_lengths = pad_field_list(
        [len(node) for node in node_rlp_bytes],
        MAX_PROOF_NODES,
    )
    padded_node_kinds = pad_field_list(
        [int(item) for item in list(private_inputs["node_kinds"])],
        MAX_PROOF_NODES,
    )
    while len(node_list_layouts) < MAX_PROOF_NODES:
        node_list_layouts.append([0, 0, 0, 0])
        node_item_layouts.append(_zero_layouts(17))
        node_compact_layouts.append([0, 0, 0, 0])
        selected_ref_layouts.append([0, 0, 0, 0])
        selected_ref_bytes.append([0] * 32)
        selected_ref_lengths.append(0)
        selected_ref_kinds.append(0)

    leaf_layout = dict(private_inputs["leaf_layout"])
    account_layout = dict(private_inputs["account_value_layout"])

    account_value_item = leaf_layout["account_value_item"]
    account_value_len = int(account_value_item["payload_len"])
    account_value = terminal_value[:account_value_len]
    if len(account_value) != account_value_len:
        raise ValueError("Terminal account value slice does not match its declared length.")

    trie_key = hex_to_bytes(str(private_inputs["address_hash"]))
    if len(trie_key) != 32:
        raise ValueError("Address hash must be 32 bytes.")

    witness = {
        "witness_version": WITNESS_VERSION,
        "public_state_root": pad_u8_list(
            list(hex_to_bytes(str(public_inputs["state_root"]))),
            32,
        ),
        "public_account_address": pad_u8_list(
            list(hex_to_bytes(str(public_inputs["account_address"]))),
            20,
        ),
        "public_hash_variant_id": int(public_inputs["hash_variant_id"]),
        "public_leaf_value_commitment": int(public_inputs["leaf_value_commitment"]),
        "private_trie_key": pad_u8_list(list(trie_key), 32),
        "private_active_node_count": active_count,
        "private_node_bytes": padded_node_bytes,
        "private_node_lengths": padded_node_lengths,
        "private_node_kinds": padded_node_kinds,
        "private_node_list_layouts": node_list_layouts,
        "private_node_item_layouts": node_item_layouts,
        "private_node_compact_layouts": node_compact_layouts,
        "private_selected_ref_layouts": selected_ref_layouts,
        "private_selected_ref_bytes": selected_ref_bytes,
        "private_selected_ref_lengths": selected_ref_lengths,
        "private_selected_ref_kinds": selected_ref_kinds,
        "private_terminal_value": pad_u8_list(list(account_value), MAX_TERMINAL_VALUE_BYTES),
        "private_terminal_value_len": account_value_len,
        "private_leaf_path_nibbles": pad_field_list(leaf_path_nibbles, ACCOUNT_PATH_NIBBLES),
        "private_leaf_path_len": leaf_path_len,
        "private_leaf_outer_list_layout": _layout4(leaf_layout["outer_list"]),
        "private_leaf_compact_path_layout": _layout4(leaf_layout["compact_path_item"]),
        "private_leaf_account_value_layout": _layout4(leaf_layout["account_value_item"]),
        "private_account_inner_list_layout": _layout4(account_layout["inner_list"]),
        "private_account_nonce_layout": _layout4(account_layout["nonce"]),
        "private_account_balance_layout": _layout4(account_layout["balance"]),
        "private_account_storage_root_layout": _layout4(account_layout["storage_root"]),
        "private_account_code_hash_layout": _layout4(account_layout["code_hash"]),
    }

    return witness


def build_poseidon2_account_inclusion_witness(
    public_inputs: dict[str, Any],
    private_inputs: dict[str, Any],
    *,
    retain_terminal_layout_fields: bool = False,
) -> dict[str, Any]:
    witness = build_keccak_account_inclusion_witness(
        {
            **public_inputs,
            "leaf_value_commitment": 0,
        },
        private_inputs,
    )
    if not retain_terminal_layout_fields:
        witness = {
            key: value
            for key, value in witness.items()
            if not (key.startswith("private_leaf_") or key.startswith("private_account_"))
        }
    public_state_root = witness.pop("public_state_root")
    public_account_address = witness.pop("public_account_address")
    public_hash_variant_id = witness.pop("public_hash_variant_id")
    witness.pop("public_leaf_value_commitment", None)

    ordered_witness: dict[str, Any] = {
        "witness_version": witness.pop("witness_version"),
        "public_state_root": public_state_root,
        "public_state_root_field": _to_field(public_inputs["state_root"]),
        "public_account_address": public_account_address,
        "public_hash_variant_id": public_hash_variant_id,
    }
    ordered_witness.update(witness)
    return ordered_witness
