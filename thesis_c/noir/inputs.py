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
from thesis_c.proof_inputs.header_anchor import HeaderAnchorFixture, build_header_anchor_witness
from thesis_c.proof_inputs.expanded_account_witness import (
    build_keccak_account_inclusion_witness,
    build_poseidon2_account_inclusion_witness,
)
from thesis_c.proof_inputs.anchored_account_inclusion import (
    build_anchored_keccak_account_inclusion_witness,
)
from thesis_c.proof_inputs.anchored_poseidon2_account_inclusion import (
    build_anchored_poseidon2_account_inclusion_witness,
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
    "eoa_activity_anchored": 6,
    "eoa_activity_anchored_poseidon2": 6,
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


def _layout4(layout: dict[str, Any]) -> list[int]:
    return [
        _to_field(layout["encoded_offset"]),
        _to_field(layout["encoded_len"]),
        _to_field(layout["payload_offset"]),
        _to_field(layout["payload_len"]),
    ]


def _bounded_account_values(
    private_inputs: dict[str, Any],
    *,
    hash_name: str,
    suffix: str = "",
) -> dict[str, Any]:
    node_rlp_hexes = list(private_inputs["node_rlp_hexes"])
    node_rlp_bytes = [hex_to_u8_list(str(item)) for item in node_rlp_hexes]
    node_rlp_lens = list(private_inputs["node_rlp_lens"])

    branch_child_hashes = [
        pad_u8_list(hex_to_u8_list(str(item)), 32)
        for item in list(private_inputs["branch_child_hashes"])
    ]
    branch_children: list[list[list[int]]] = []
    for branch in list(private_inputs["branch_children"]):
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

    leaf_layout = dict(private_inputs["leaf_layout"])
    account_layout = dict(private_inputs["account_value_layout"])
    values = {
        f"private_node_rlp_bytes{suffix}": pad_nested_u8_lists(
            node_rlp_bytes,
            MAX_ACCOUNT_PROOF_NODES,
            MAX_ACCOUNT_NODE_BYTES,
        ),
        f"private_node_rlp_lens{suffix}": pad_field_list(
            [_to_field(item) for item in node_rlp_lens],
            MAX_ACCOUNT_PROOF_NODES,
        ),
        f"private_node_kinds{suffix}": pad_field_list(
            [_to_field(item) for item in list(private_inputs["node_kinds"])],
            MAX_ACCOUNT_PROOF_NODES,
        ),
        f"private_branch_child_indices{suffix}": pad_field_list(
            [_to_field(item) for item in list(private_inputs["branch_child_indices"])],
            MAX_ACCOUNT_PROOF_NODES - 1,
        ),
        f"private_branch_child_hashes{suffix}": pad_nested_u8_lists(
            branch_child_hashes,
            MAX_ACCOUNT_PROOF_NODES - 1,
            32,
        ),
        f"private_branch_children{suffix}": branch_children,
        f"private_path_nibbles{suffix}": pad_field_list(
            [_to_field(item) for item in list(private_inputs["path_nibbles"])],
            ACCOUNT_PATH_NIBBLES,
        ),
        f"private_leaf_path_nibbles{suffix}": pad_field_list(
            [_to_field(item) for item in list(private_inputs["leaf_path_nibbles"])],
            MAX_LEAF_PATH_NIBBLES,
        ),
        f"private_leaf_path_len{suffix}": _to_field(private_inputs["leaf_path_len"]),
        f"private_leaf_outer_list_layout{suffix}": _layout4(leaf_layout["outer_list"]),
        f"private_leaf_compact_path_layout{suffix}": _layout4(leaf_layout["compact_path_item"]),
        f"private_leaf_account_value_layout{suffix}": _layout4(leaf_layout["account_value_item"]),
        f"private_account_inner_list_layout{suffix}": _layout4(account_layout["inner_list"]),
        f"private_account_nonce_layout{suffix}": _layout4(account_layout["nonce"]),
        f"private_account_balance_layout{suffix}": _layout4(account_layout["balance"]),
        f"private_account_storage_root_layout{suffix}": _layout4(account_layout["storage_root"]),
        f"private_account_code_hash_layout{suffix}": _layout4(account_layout["code_hash"]),
    }

    if "account_proof_depth" in private_inputs:
        values[f"private_account_proof_depth{suffix}"] = _to_field(
            private_inputs["account_proof_depth"]
        )

    if hash_name == "poseidon2":
        branch_child_hash_fields = [
            _to_field(item) for item in list(private_inputs["branch_child_hashes"])
        ]
        while len(branch_child_hash_fields) < MAX_ACCOUNT_PROOF_NODES - 1:
            branch_child_hash_fields.append(0)

        branch_children_fields: list[list[int]] = []
        for branch in list(private_inputs["branch_children"]):
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

        values[f"private_branch_child_hash_fields{suffix}"] = branch_child_hash_fields
        values[f"private_branch_children_fields{suffix}"] = branch_children_fields
        values[f"private_address_hash{suffix}"] = pad_u8_list(
            hex_to_u8_list(str(private_inputs["address_hash"])),
            32,
        )

    return values


def _expanded_eoa_state_values(
    *,
    hash_name: str,
    suffix: str,
    state_root: str,
    account_address: str,
    hash_variant_id: int,
    private_inputs: dict[str, Any],
) -> dict[str, Any]:
    state_public_inputs = {
        "state_root": state_root,
        "account_address": account_address,
        "hash_variant_id": hash_variant_id,
        "leaf_value_commitment": 0,
    }
    if hash_name == "poseidon2":
        witness = build_poseidon2_account_inclusion_witness(
            state_public_inputs,
            private_inputs,
            retain_terminal_layout_fields=True,
        )
    else:
        witness = build_keccak_account_inclusion_witness(
            state_public_inputs,
            private_inputs,
        )

    values: dict[str, Any] = {"witness_version": witness.pop("witness_version")}
    if "public_state_root_field" in witness:
        values[f"public_state_root_field{suffix}"] = witness.pop("public_state_root_field")

    for key, value in witness.items():
        if key.startswith("public_"):
            continue
        values[f"{key}{suffix}"] = value

    if hash_name == "poseidon2":
        values[f"private_address_hash{suffix}"] = values[f"private_trie_key{suffix}"]
        values[f"private_branch_child_hash_fields{suffix}"] = [
            _to_field(bytes(item)) for item in values[f"private_selected_ref_bytes{suffix}"][:3]
        ]
        values[f"private_branch_children_fields{suffix}"] = [
            [_to_field(slot) for slot in list(branch)]
            for branch in list(private_inputs["branch_children"])
        ]

    return values


def _strip_anchored_header_private_inputs(private_inputs: dict[str, Any]) -> dict[str, Any]:
    stripped = dict(private_inputs)
    stripped.pop("header_anchor", None)
    stripped.pop("header_anchor_1", None)
    stripped.pop("header_anchor_2", None)
    stripped.pop("header_witness_version", None)
    stripped.pop("header_witness_version_1", None)
    stripped.pop("header_witness_version_2", None)
    stripped.pop("private_header_bytes", None)
    stripped.pop("private_header_bytes_1", None)
    stripped.pop("private_header_bytes_2", None)
    stripped.pop("private_header_len", None)
    stripped.pop("private_header_len_1", None)
    stripped.pop("private_header_len_2", None)
    return stripped


def _anchored_header_values(
    *,
    private_inputs: dict[str, Any],
    suffix: str,
) -> dict[str, Any]:
    header_anchor = HeaderAnchorFixture(**private_inputs[f"header_anchor{suffix}"])
    witness = build_header_anchor_witness(header_anchor)
    return {
        f"public_block_hash{suffix}": witness["public_block_hash"],
        f"header_witness_version{suffix}": witness["witness_version"],
        f"private_header_bytes{suffix}": witness["private_header_bytes"],
        f"private_header_len{suffix}": witness["private_header_len"],
    }


def to_noir_input_map(statement: PreparedStatement) -> dict[str, Any]:
    """
    Convert a PreparedStatement to a stable fixed-shape map suitable for Prover.toml.
    This avoids statement-specific ABI churn while preserving statement/hash metadata.
    """
    hash_name = str(statement.public_inputs.get("hash_name", "")).lower()

    if statement.statement_name == "account_inclusion":
        if hash_name == "keccak256":
            return build_keccak_account_inclusion_witness(
                statement.public_inputs,
                statement.private_inputs,
            )
        return build_poseidon2_account_inclusion_witness(
            statement.public_inputs,
            statement.private_inputs,
        )

    if statement.statement_name == "account_inclusion_anchored":
        if hash_name != "keccak256":
            raise ValueError(
                "Anchored account inclusion currently supports keccak256 only."
            )
        return build_anchored_keccak_account_inclusion_witness(
            statement.public_inputs,
            statement.private_inputs,
        )

    if statement.statement_name == "account_inclusion_anchored_poseidon2":
        if hash_name != "poseidon2":
            raise ValueError(
                "Anchored Poseidon2 account inclusion currently supports poseidon2 only."
            )
        return build_anchored_poseidon2_account_inclusion_witness(
            statement.public_inputs,
            statement.private_inputs,
        )

    if statement.statement_name == "balance_verification_anchored":
        public_inputs = dict(statement.public_inputs)
        private_inputs = _strip_anchored_header_private_inputs(dict(statement.private_inputs))
        temp_statement = PreparedStatement(
            statement_name="balance_verification",
            public_inputs={
                key: value
                for key, value in public_inputs.items()
                if key != "block_hash"
            },
            private_inputs=private_inputs,
            metadata=dict(statement.metadata),
        )
        account_witness = to_noir_input_map(temp_statement)
        block_hash = pad_u8_list(
            hex_to_u8_list(str(public_inputs["block_hash"])),
            32,
        )
        header_witness_version = _to_field(statement.private_inputs["header_witness_version"])
        private_header_bytes = pad_u8_list(
            list(statement.private_inputs["private_header_bytes"]),
            640,
        )
        private_header_len = _to_field(statement.private_inputs["private_header_len"])
        account_witness_version = account_witness.pop("witness_version")
        public_state_root = account_witness.pop("public_state_root")
        public_account_address = account_witness.pop("public_account_address")
        public_claimed_balance_limbs = account_witness.pop("public_claimed_balance_limbs")
        public_hash_variant_id = account_witness.pop("public_hash_variant_id")
        values: dict[str, Any] = {
            "public_block_hash": block_hash,
            "public_state_root": public_state_root,
            "public_account_address": public_account_address,
            "public_claimed_balance_limbs": public_claimed_balance_limbs,
            "public_hash_variant_id": public_hash_variant_id,
            "header_witness_version": header_witness_version,
            "private_header_bytes": private_header_bytes,
            "private_header_len": private_header_len,
            "account_witness_version": account_witness_version,
        }
        if "public_state_root_field" in account_witness:
            values["public_state_root_field"] = account_witness.pop("public_state_root_field")
        values.update(account_witness)
        return values

    if statement.statement_name == "balance_verification_anchored_poseidon2":
        public_inputs = dict(statement.public_inputs)
        private_inputs = _strip_anchored_header_private_inputs(dict(statement.private_inputs))
        temp_statement = PreparedStatement(
            statement_name="balance_verification",
            public_inputs={
                key: value
                for key, value in public_inputs.items()
                if key != "block_hash"
            },
            private_inputs=private_inputs,
            metadata=dict(statement.metadata),
        )
        account_witness = to_noir_input_map(temp_statement)
        block_hash = pad_u8_list(
            hex_to_u8_list(str(public_inputs["block_hash"])),
            32,
        )
        header_witness_version = _to_field(statement.private_inputs["header_witness_version"])
        private_header_bytes = pad_u8_list(
            list(statement.private_inputs["private_header_bytes"]),
            640,
        )
        private_header_len = _to_field(statement.private_inputs["private_header_len"])
        account_witness_version = account_witness.pop("witness_version")
        public_state_root = account_witness.pop("public_state_root")
        public_state_root_field = account_witness.pop("public_state_root_field")
        public_account_address = account_witness.pop("public_account_address")
        public_claimed_balance_limbs = account_witness.pop("public_claimed_balance_limbs")
        public_hash_variant_id = account_witness.pop("public_hash_variant_id")
        values = {
            "public_block_hash": block_hash,
            "public_state_root": public_state_root,
            "public_state_root_field": public_state_root_field,
            "public_account_address": public_account_address,
            "public_claimed_balance_limbs": public_claimed_balance_limbs,
            "public_hash_variant_id": public_hash_variant_id,
            "header_witness_version": header_witness_version,
            "private_header_bytes": private_header_bytes,
            "private_header_len": private_header_len,
            "account_witness_version": account_witness_version,
        }
        values.update(account_witness)
        return values

    if statement.statement_name == "codehash_verification_anchored":
        public_inputs = dict(statement.public_inputs)
        private_inputs = _strip_anchored_header_private_inputs(dict(statement.private_inputs))
        temp_statement = PreparedStatement(
            statement_name="codehash_verification",
            public_inputs={
                key: value
                for key, value in public_inputs.items()
                if key != "block_hash"
            },
            private_inputs=private_inputs,
            metadata=dict(statement.metadata),
        )
        account_witness = to_noir_input_map(temp_statement)
        block_hash = pad_u8_list(
            hex_to_u8_list(str(public_inputs["block_hash"])),
            32,
        )
        header_witness_version = _to_field(statement.private_inputs["header_witness_version"])
        private_header_bytes = pad_u8_list(
            list(statement.private_inputs["private_header_bytes"]),
            640,
        )
        private_header_len = _to_field(statement.private_inputs["private_header_len"])
        account_witness_version = account_witness.pop("witness_version")
        public_state_root = account_witness.pop("public_state_root")
        public_account_address = account_witness.pop("public_account_address")
        public_expected_code_hash = account_witness.pop("public_expected_code_hash")
        public_hash_variant_id = account_witness.pop("public_hash_variant_id")
        values = {
            "public_block_hash": block_hash,
            "public_state_root": public_state_root,
            "public_account_address": public_account_address,
            "public_expected_code_hash": public_expected_code_hash,
            "public_hash_variant_id": public_hash_variant_id,
            "header_witness_version": header_witness_version,
            "private_header_bytes": private_header_bytes,
            "private_header_len": private_header_len,
            "account_witness_version": account_witness_version,
        }
        if "public_state_root_field" in account_witness:
            values["public_state_root_field"] = account_witness.pop("public_state_root_field")
        values.update(account_witness)
        return values

    if statement.statement_name == "codehash_verification_anchored_poseidon2":
        public_inputs = dict(statement.public_inputs)
        private_inputs = _strip_anchored_header_private_inputs(dict(statement.private_inputs))
        temp_statement = PreparedStatement(
            statement_name="codehash_verification",
            public_inputs={
                key: value
                for key, value in public_inputs.items()
                if key != "block_hash"
            },
            private_inputs=private_inputs,
            metadata=dict(statement.metadata),
        )
        account_witness = to_noir_input_map(temp_statement)
        block_hash = pad_u8_list(
            hex_to_u8_list(str(public_inputs["block_hash"])),
            32,
        )
        header_witness_version = _to_field(statement.private_inputs["header_witness_version"])
        private_header_bytes = pad_u8_list(
            list(statement.private_inputs["private_header_bytes"]),
            640,
        )
        private_header_len = _to_field(statement.private_inputs["private_header_len"])
        account_witness_version = account_witness.pop("witness_version")
        public_state_root = account_witness.pop("public_state_root")
        public_state_root_field = account_witness.pop("public_state_root_field")
        public_account_address = account_witness.pop("public_account_address")
        public_expected_code_hash = account_witness.pop("public_expected_code_hash")
        public_hash_variant_id = account_witness.pop("public_hash_variant_id")
        values = {
            "public_block_hash": block_hash,
            "public_state_root": public_state_root,
            "public_state_root_field": public_state_root_field,
            "public_account_address": public_account_address,
            "public_expected_code_hash": public_expected_code_hash,
            "public_hash_variant_id": public_hash_variant_id,
            "header_witness_version": header_witness_version,
            "private_header_bytes": private_header_bytes,
            "private_header_len": private_header_len,
            "account_witness_version": account_witness_version,
        }
        values.update(account_witness)
        return values

    if statement.statement_name == "balance_verification":
        claimed_balance_limbs = [
            _to_field(item) for item in list(statement.public_inputs["claimed_balance_limbs"])
        ]
        if len(claimed_balance_limbs) != 4:
            raise ValueError(
                "Balance verification public claimed balance must contain exactly four u64 limbs."
            )
        public_inputs = dict(statement.public_inputs)
        private_inputs = dict(statement.private_inputs)
        hash_name = str(public_inputs.get("hash_name", "")).lower()

        if hash_name == "keccak256":
            account_witness = build_keccak_account_inclusion_witness(
                {**public_inputs, "leaf_value_commitment": 0},
                private_inputs,
            )
        elif hash_name == "poseidon2":
            account_witness = build_poseidon2_account_inclusion_witness(
                {**public_inputs, "leaf_value_commitment": 0},
                private_inputs,
            )
        else:
            raise ValueError(f"Unsupported hash variant for balance verification: {hash_name}")

        values: dict[str, Any] = {
            "witness_version": account_witness["witness_version"],
            "public_state_root": account_witness["public_state_root"],
        }
        if "public_state_root_field" in account_witness:
            values["public_state_root_field"] = account_witness["public_state_root_field"]
        values["public_account_address"] = account_witness["public_account_address"]
        values["public_claimed_balance_limbs"] = claimed_balance_limbs
        values["public_hash_variant_id"] = account_witness["public_hash_variant_id"]
        values["private_account_proof_depth"] = private_inputs["account_proof_depth"]

        skip_keys = {
            "witness_version",
            "public_state_root",
            "public_state_root_field",
            "public_account_address",
            "public_hash_variant_id",
            "private_account_proof_depth",
            "public_leaf_value_commitment",
            "private_leaf_outer_list_layout",
            "private_leaf_compact_path_layout",
            "private_leaf_account_value_layout",
            "private_account_inner_list_layout",
            "private_account_nonce_layout",
            "private_account_balance_layout",
            "private_account_storage_root_layout",
            "private_account_code_hash_layout",
        }
        for key, value in account_witness.items():
            if key not in skip_keys and not key.startswith("private_leaf_") and not key.startswith("private_account_"):
                values[key] = value

        leaf_layout = dict(private_inputs["leaf_layout"])
        account_layout = dict(private_inputs["account_value_layout"])
        values["private_leaf_outer_list_layout"] = _layout4(leaf_layout["outer_list"])
        values["private_leaf_compact_path_layout"] = _layout4(leaf_layout["compact_path_item"])
        values["private_leaf_account_value_layout"] = _layout4(leaf_layout["account_value_item"])
        values["private_account_inner_list_layout"] = _layout4(account_layout["inner_list"])
        values["private_account_nonce_layout"] = _layout4(account_layout["nonce"])
        values["private_account_balance_layout"] = _layout4(account_layout["balance"])
        values["private_account_storage_root_layout"] = _layout4(account_layout["storage_root"])
        values["private_account_code_hash_layout"] = _layout4(account_layout["code_hash"])
        return values

    if statement.statement_name == "codehash_verification":
        public_inputs = dict(statement.public_inputs)
        private_inputs = dict(statement.private_inputs)
        public_inputs["leaf_value_commitment"] = 0
        expected_code_hash = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["expected_code_hash"])),
            32,
        )
        if hash_name == "keccak256":
            witness = build_keccak_account_inclusion_witness(public_inputs, private_inputs)
            witness.pop("public_leaf_value_commitment", None)
            account_witness_version = witness.pop("witness_version")
            ordered_witness: dict[str, Any] = {
                "witness_version": account_witness_version,
                "account_witness_version": account_witness_version,
                "public_state_root": witness.pop("public_state_root"),
                "public_account_address": witness.pop("public_account_address"),
                "public_expected_code_hash": expected_code_hash,
                "public_hash_variant_id": witness.pop("public_hash_variant_id"),
            }
            ordered_witness.update(witness)
            return ordered_witness
        if hash_name == "poseidon2":
            witness = build_keccak_account_inclusion_witness(public_inputs, private_inputs)
            witness.pop("public_leaf_value_commitment", None)
            account_witness_version = witness.pop("witness_version")
            public_state_root_field = _to_field(statement.public_inputs["state_root"])
            ordered_witness = {
                "witness_version": account_witness_version,
                "account_witness_version": account_witness_version,
                "public_state_root": witness.pop("public_state_root"),
                "public_state_root_field": public_state_root_field,
                "public_account_address": witness.pop("public_account_address"),
                "public_expected_code_hash": expected_code_hash,
                "public_hash_variant_id": witness.pop("public_hash_variant_id"),
                "private_state_root_field": public_state_root_field,
            }
            ordered_witness["private_address_hash"] = witness["private_trie_key"]
            ordered_witness.update(witness)
            return ordered_witness
        raise ValueError(f"Unsupported hash variant for codehash verification: {hash_name}")

    if statement.statement_name == "eoa_activity":
        hash_variant_id = _to_field(statement.public_inputs["hash_variant_id"])
        values = _expanded_eoa_state_values(
            hash_name=hash_name,
            suffix="_1",
            state_root=str(statement.public_inputs["state_root_1"]),
            account_address=str(statement.public_inputs["account_address"]),
            hash_variant_id=hash_variant_id,
            private_inputs=dict(statement.private_inputs["state_1"]),
        )
        values["public_hash_variant_id"] = hash_variant_id
        values["public_account_address"] = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["account_address"])),
            20,
        )
        values["public_state_root_1"] = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["state_root_1"])),
            32,
        )
        values["public_state_root_2"] = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["state_root_2"])),
            32,
        )
        if hash_name == "poseidon2":
            values["public_state_root_1_field"] = _to_field(
                statement.public_inputs["state_root_1"]
            )
            values["public_state_root_2_field"] = _to_field(
                statement.public_inputs["state_root_2"]
            )
        values.update(
            _expanded_eoa_state_values(
                hash_name=hash_name,
                suffix="_2",
                state_root=str(statement.public_inputs["state_root_2"]),
                account_address=str(statement.public_inputs["account_address"]),
                hash_variant_id=hash_variant_id,
                private_inputs=dict(statement.private_inputs["state_2"]),
            )
        )
        return values

    if statement.statement_name in {
        "eoa_activity_anchored",
        "eoa_activity_anchored_poseidon2",
    }:
        hash_variant_id = _to_field(statement.public_inputs["hash_variant_id"])
        state_1 = _expanded_eoa_state_values(
            hash_name=hash_name,
            suffix="_1",
            state_root=str(statement.public_inputs["state_root_1"]),
            account_address=str(statement.public_inputs["account_address"]),
            hash_variant_id=hash_variant_id,
            private_inputs=dict(statement.private_inputs["state_1"]),
        )
        state_2 = _expanded_eoa_state_values(
            hash_name=hash_name,
            suffix="_2",
            state_root=str(statement.public_inputs["state_root_2"]),
            account_address=str(statement.public_inputs["account_address"]),
            hash_variant_id=hash_variant_id,
            private_inputs=dict(statement.private_inputs["state_2"]),
        )
        if hash_name == "poseidon2":
            state_1.pop("public_state_root_field_1", None)
            state_2.pop("public_state_root_field_2", None)
        header_1 = _anchored_header_values(private_inputs=statement.private_inputs, suffix="_1")
        header_2 = _anchored_header_values(private_inputs=statement.private_inputs, suffix="_2")

        values = {
            "witness_version": state_1.pop("witness_version"),
            "public_block_hash_1": header_1["public_block_hash_1"],
            "public_state_root_1": pad_u8_list(
                hex_to_u8_list(str(statement.public_inputs["state_root_1"])),
                32,
            ),
        }
        if hash_name == "poseidon2":
            values["public_state_root_1_field"] = _to_field(
                statement.public_inputs["state_root_1"]
            )
        values["public_block_hash_2"] = header_2["public_block_hash_2"]
        values["public_state_root_2"] = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["state_root_2"])),
            32,
        )
        if hash_name == "poseidon2":
            values["public_state_root_2_field"] = _to_field(
                statement.public_inputs["state_root_2"]
            )
        values["public_account_address"] = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["account_address"])),
            20,
        )
        values["public_hash_variant_id"] = hash_variant_id
        values["header_witness_version_1"] = header_1["header_witness_version_1"]
        values["private_header_bytes_1"] = header_1["private_header_bytes_1"]
        values["private_header_len_1"] = header_1["private_header_len_1"]
        values["account_witness_version_1"] = values["witness_version"]
        values.update(state_1)
        values["header_witness_version_2"] = header_2["header_witness_version_2"]
        values["private_header_bytes_2"] = header_2["private_header_bytes_2"]
        values["private_header_len_2"] = header_2["private_header_len_2"]
        values["account_witness_version_2"] = state_2["witness_version"]
        values.update(state_2)
        return values

    if statement.statement_name == "storage_slot_membership":
        public_hash_variant_id = _to_field(statement.public_inputs["hash_variant_id"])
        public_state_root = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["state_root"])), 32
        )
        public_contract_address = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["contract_address"])), 20
        )
        public_storage_slot = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["storage_slot"])), 32
        )
        public_expected_storage_value = pad_u8_list(
            hex_to_u8_list(str(statement.public_inputs["expected_storage_value"])), 32
        )
        values = {
            "public_hash_variant_id": public_hash_variant_id,
            "public_state_root": public_state_root,
            **({"public_state_root_field": _to_field(statement.public_inputs["state_root"])} if hash_name == "poseidon2" else {}),
            "public_contract_address": public_contract_address,
            "public_storage_slot": public_storage_slot,
            "public_expected_storage_value": public_expected_storage_value,
            **_bounded_account_values(
                statement.private_inputs,
                hash_name=hash_name,
            ),
        }

        storage_nodes = [
            hex_to_u8_list(str(item))
            for item in list(statement.private_inputs["storage_node_rlp_hexes"])
        ]
        storage_lens = list(statement.private_inputs["storage_node_rlp_lens"])
        storage_layout = dict(statement.private_inputs["storage_leaf_layout"])
        values.update(
            {
                "private_storage_node_rlp_bytes": pad_nested_u8_lists(
                    storage_nodes, 1, MAX_ACCOUNT_NODE_BYTES
                ),
                "private_storage_node_rlp_len": _to_field(storage_lens[0]),
                "private_storage_proof_depth": _to_field(
                    statement.private_inputs["storage_proof_depth"]
                ),
                "private_storage_path_nibbles": pad_field_list(
                    [_to_field(item) for item in statement.private_inputs["storage_path_nibbles"]],
                    ACCOUNT_PATH_NIBBLES,
                ),
                "private_storage_path_len": _to_field(
                    statement.private_inputs["storage_path_len"]
                ),
                "private_storage_leaf_outer_list_layout": _layout4(
                    storage_layout["outer_list"]
                ),
                "private_storage_leaf_compact_path_layout": _layout4(
                    storage_layout["compact_path_item"]
                ),
                "private_storage_value_item_layout": _layout4(
                    storage_layout["value_item"]
                ),
                "private_storage_value_payload_offset": _to_field(
                    statement.private_inputs["storage_value_payload_offset"]
                ),
                "private_storage_value_payload_len": _to_field(
                    statement.private_inputs["storage_value_payload_len"]
                ),
                "private_storage_value_active_bytes": pad_u8_list(
                    list(statement.private_inputs["storage_value_active_bytes"]), 32
                ),
                "private_storage_value_active_len": _to_field(
                    statement.private_inputs["storage_value_active_len"]
                ),
                "private_storage_value_padded": pad_u8_list(
                    list(statement.private_inputs["storage_value_padded"]), 32
                ),
                "private_storage_key_hash": pad_u8_list(
                    hex_to_u8_list(str(statement.private_inputs["storage_key_hash"])), 32
                ),
            }
        )
        if hash_name == "poseidon2":
            values["private_storage_key_field"] = _to_field(
                statement.private_inputs["storage_key_hash"]
            )
            values["private_storage_leaf_hash_field"] = _to_field(
                statement.private_inputs["storage_node_hash"]
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
