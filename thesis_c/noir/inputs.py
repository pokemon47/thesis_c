from __future__ import annotations

import hashlib
import json
from typing import Any

from thesis_c.proof_inputs.normalizer import (
    ACCOUNT_PATH_NIBBLES,
    MAX_ACCOUNT_NODE_BYTES,
    MAX_ACCOUNT_PROOF_NODES,
    MAX_LEAF_PATH_NIBBLES,
    hex_to_u8_list,
    pad_field_list,
    pad_nested_u8_lists,
    pad_u8_list,
)
from thesis_c.proof_inputs.schema import PreparedStatement


BN254_FIELD_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

BRANCH_CHILD_SLOTS = 16

STATEMENT_SELECTOR = {
    "account_inclusion": 1,
    "balance_verification": 2,
    "codehash_verification": 3,
    "eoa_activity": 4,
    "storage_slot_membership": 5,
}

HASH_SELECTOR = {
    "keccak256": 1,
    "poseidon2": 2,
}


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


def _commit(value: Any) -> int:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).digest()
    return int.from_bytes(digest, "big") % BN254_FIELD_MODULUS


def to_noir_input_map(statement: PreparedStatement) -> dict[str, Any]:
    """
    Convert a PreparedStatement to a stable fixed-shape map suitable for Prover.toml.
    This avoids statement-specific ABI churn while preserving statement/hash metadata.
    """
    hash_name = str(statement.public_inputs.get("hash_name", "")).lower()

    if statement.statement_name == "account_inclusion":
        state_root = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["state_root"])),
            32,
        )
        account_address = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["account_address"])),
            20,
        )
        node_rlp_hexes = list(statement.private_inputs["node_rlp_hexes"])
        node_rlp_bytes = [hex_to_u8_list(str(item)) for item in node_rlp_hexes]
        node_rlp_lens = list(statement.private_inputs["node_rlp_lens"])

        private_storage_root = pad_u8_list(
            hex_to_u8_list(str(statement.private_inputs["storage_root"])),
            32,
        )
        private_code_hash = pad_u8_list(
            hex_to_u8_list(str(statement.private_inputs["code_hash"])),
            32,
        )
        branch_child_hashes = [
            pad_u8_list(hex_to_u8_list(str(item)), 32)
            for item in list(statement.private_inputs["branch_child_hashes"])
        ]
        branch_children: list[list[list[int]]] = []
        for branch in list(statement.private_inputs["branch_children"]):
            padded_slots = [
                pad_u8_list(hex_to_u8_list(str(slot)), 32) for slot in list(branch)
            ]
            if len(padded_slots) > BRANCH_CHILD_SLOTS:
                raise ValueError(
                    f"Branch child slot count {len(padded_slots)} exceeds {BRANCH_CHILD_SLOTS}"
                )
            while len(padded_slots) < BRANCH_CHILD_SLOTS:
                padded_slots.append([0] * 32)
            branch_children.append(padded_slots)
        if len(branch_children) > MAX_ACCOUNT_PROOF_NODES - 1:
            raise ValueError(
                f"Branch node count {len(branch_children)} exceeds {MAX_ACCOUNT_PROOF_NODES - 1}"
            )
        while len(branch_children) < MAX_ACCOUNT_PROOF_NODES - 1:
            branch_children.append([[0] * 32 for _ in range(BRANCH_CHILD_SLOTS)])

        values = {
            "public_state_root": state_root,
            "public_account_address": account_address,
            "public_hash_variant_id": _to_field(statement.public_inputs["hash_variant_id"]),
            "public_leaf_value_commitment": _to_field(
                statement.public_inputs["leaf_value_commitment"]
            ),
            "private_node_rlp_bytes": pad_nested_u8_lists(
                node_rlp_bytes,
                MAX_ACCOUNT_PROOF_NODES,
                MAX_ACCOUNT_NODE_BYTES,
            ),
            "private_node_rlp_lens": pad_field_list(
                [_to_field(item) for item in node_rlp_lens],
                MAX_ACCOUNT_PROOF_NODES,
            ),
            "private_node_kinds": pad_field_list(
                [_to_field(item) for item in list(statement.private_inputs["node_kinds"])],
                MAX_ACCOUNT_PROOF_NODES,
            ),
            "private_branch_child_indices": pad_field_list(
                [_to_field(item) for item in list(statement.private_inputs["branch_child_indices"])],
                MAX_ACCOUNT_PROOF_NODES - 1,
            ),
            "private_branch_child_hashes": pad_nested_u8_lists(
                branch_child_hashes,
                MAX_ACCOUNT_PROOF_NODES - 1,
                32,
            ),
            "private_branch_children": branch_children,
            "private_path_nibbles": pad_field_list(
                [_to_field(item) for item in list(statement.private_inputs["path_nibbles"])],
                ACCOUNT_PATH_NIBBLES,
            ),
            "private_leaf_path_nibbles": pad_field_list(
                [_to_field(item) for item in list(statement.private_inputs["leaf_path_nibbles"])],
                MAX_LEAF_PATH_NIBBLES,
            ),
            "private_leaf_path_len": _to_field(statement.private_inputs["leaf_path_len"]),
            "private_nonce": _to_field(statement.private_inputs["nonce"]),
            "private_balance": _to_field(statement.private_inputs["balance"]),
            "private_storage_root": private_storage_root,
            "private_code_hash": private_code_hash,
        }

        if hash_name == "poseidon2":
            branch_child_hash_fields = [
                _to_field(item) for item in list(statement.private_inputs["branch_child_hashes"])
            ]
            while len(branch_child_hash_fields) < MAX_ACCOUNT_PROOF_NODES - 1:
                branch_child_hash_fields.append(0)

            branch_children_fields: list[list[int]] = []
            for branch in list(statement.private_inputs["branch_children"]):
                slots = [_to_field(slot) for slot in list(branch)]
                if len(slots) > BRANCH_CHILD_SLOTS:
                    raise ValueError(
                        f"Branch child slot count {len(slots)} exceeds {BRANCH_CHILD_SLOTS}"
                    )
                while len(slots) < BRANCH_CHILD_SLOTS:
                    slots.append(0)
                branch_children_fields.append(slots)
            while len(branch_children_fields) < MAX_ACCOUNT_PROOF_NODES - 1:
                branch_children_fields.append([0] * BRANCH_CHILD_SLOTS)

            values["public_state_root_field"] = _to_field(
                statement.public_inputs["state_root"]
            )
            values["private_branch_child_hash_fields"] = branch_child_hash_fields
            values["private_branch_children_fields"] = branch_children_fields
            values["private_address_hash"] = pad_u8_list(
                hex_to_u8_list(str(statement.private_inputs["address_hash"])),
                32,
            )

        return values

    public_commitment = _commit(statement.public_inputs)
    private_commitment = _commit(statement.private_inputs)
    metadata_commitment = _commit(statement.metadata)
    return {
        "public_statement_selector": STATEMENT_SELECTOR.get(statement.statement_name, 0),
        "public_hash_selector": HASH_SELECTOR.get(hash_name, _to_field(hash_name)),
        "public_expected_commitment": public_commitment,
        "private_observed_commitment": private_commitment,
        "private_aux_commitment": metadata_commitment,
    }
