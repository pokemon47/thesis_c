from __future__ import annotations

from dataclasses import asdict

from thesis_c.baseline.account_layout import payload_slice
from thesis_c.baseline.account_verifier import variable_depth_account_precheck
from thesis_c.baseline.storage_layout import (
    derive_storage_trie_key,
    parse_one_node_storage_leaf,
    storage_slot_bytes,
)
from thesis_c.baseline.verifier_adapter import verify_storage_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.proof_inputs.normalizer import hex_to_bytes, normalize_hex
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.statements.base import ProofStatement


class StorageSlotMembershipStatement(ProofStatement):
    name = "storage_slot_membership"

    def __init__(self, expected_storage_value: str | int | None = None) -> None:
        self.expected_storage_value = expected_storage_value

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        baseline = baseline_results[0]
        if len(payloads) != 1 or len(baseline_results) != 1:
            raise ValueError("Storage slot membership requires exactly one payload.")
        if not baseline.ok or baseline.leaf is None:
            raise ValueError(
                f"Baseline verification failed for storage slot membership: {baseline.error}"
            )
        if len(payload.storage_proof) != 1:
            raise ValueError("Storage slot membership requires exactly one storageProof entry.")

        hash_name = baseline.hash_name.lower()
        if hash_name == "keccak256":
            hash_variant = Keccak256Hash()
            hash_variant_id = 1
        elif hash_name == "poseidon2":
            hash_variant = Poseidon2Hash.from_environment()
            hash_variant_id = 2
        else:
            raise ValueError(f"Unsupported hash variant for storage membership: {hash_name}")

        account_prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
        authenticated = variable_depth_account_precheck(payload, hash_variant)
        leaf_node = authenticated.terminal_node_bytes
        authenticated_storage_root = payload_slice(
            leaf_node, authenticated.account_layout.storage_root
        )
        if authenticated_storage_root.hex() != baseline.leaf.storage_root[2:]:
            raise ValueError("authenticated_storage_root_mismatch")
        if payload.storage_hash and normalize_hex(payload.storage_hash) != normalize_hex(
            baseline.leaf.storage_root
        ):
            raise ValueError("external_storage_root_consistency_mismatch")
        if payload.state_root and normalize_hex(payload.state_root) != normalize_hex(
            baseline.state_root
        ):
            raise ValueError("external_state_root_consistency_mismatch")

        first_entry = payload.storage_proof[0]
        storage_result = verify_storage_payload(payload, hash_variant)
        if not storage_result.ok:
            raise ValueError(f"Baseline storage verification failed: {storage_result.error}")
        if len(first_entry.proof) != 1:
            raise ValueError("storage_proof_must_contain_exactly_one_node")

        slot_bytes = storage_slot_bytes(first_entry.key)
        storage_key = derive_storage_trie_key(first_entry.key, hash_variant)
        storage_node = hex_to_bytes(first_entry.proof[0])
        storage_path = [nibble for byte in storage_key for nibble in (byte >> 4, byte & 0x0F)]
        storage_layout = parse_one_node_storage_leaf(
            storage_node,
            expected_path=storage_path,
            storage_root=authenticated_storage_root,
            hash_variant=hash_variant,
        )

        if self.expected_storage_value is None:
            expected_value = storage_layout.decoded_value
        elif isinstance(self.expected_storage_value, str):
            expected_value = int(self.expected_storage_value, 0)
        else:
            expected_value = int(self.expected_storage_value)
        if expected_value < 0 or expected_value >= 1 << 256:
            raise ValueError("expected_storage_value_out_of_range")
        if expected_value != storage_layout.decoded_value:
            raise ValueError("expected_storage_value_mismatch")
        padded_value = storage_layout.active_value_bytes.rjust(32, b"\x00")

        private_inputs = dict(account_prepared.private_inputs)
        private_inputs.update(
            {
                "storage_node_rlp_hexes": ["0x" + storage_node.hex()],
                "storage_node_rlp_lens": [storage_layout.leaf_node_len],
                "storage_proof_depth": 1,
                "storage_path_nibbles": storage_path,
                "storage_path_len": len(storage_path),
                "storage_leaf_layout": {
                    "outer_list": asdict(storage_layout.outer_list),
                    "compact_path_item": asdict(storage_layout.compact_path_item),
                    "value_item": asdict(storage_layout.value_item),
                },
                "storage_value_payload_offset": storage_layout.value_payload_offset,
                "storage_value_payload_len": storage_layout.value_payload_len,
                "storage_value_active_bytes": list(storage_layout.active_value_bytes),
                "storage_value_active_len": storage_layout.active_value_len,
                "storage_value_padded": list(padded_value),
                "storage_key_bytes": list(slot_bytes),
                "storage_key_hash": "0x" + storage_key.hex(),
                "storage_node_hash": "0x" + hash_variant.digest(storage_node).hex(),
            }
        )

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "contract_address": payload.address,
                "state_root": baseline.state_root,
                "storage_slot": "0x" + slot_bytes.hex(),
                "expected_storage_value": "0x" + padded_value.hex(),
                "hash_name": baseline.hash_name,
                "hash_variant_id": hash_variant_id,
            },
            private_inputs=private_inputs,
            metadata={
                "source_file": payload.source_file,
                "source_index": payload.source_index,
                "block_number": payload.block_number,
                "proof_mode": "baseline_verified_storage_membership_one_node",
                "storage_proof_shape": "one_terminal_leaf",
                "storage_root_source": "authenticated_account_field_2",
            },
        )
