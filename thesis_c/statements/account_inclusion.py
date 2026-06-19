from __future__ import annotations

import rlp

from thesis_c.baseline.verifier_adapter import (
    bounded_account_precheck,
    bytes_to_nibbles,
    decode_compact_with_flags,
)
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.proof_inputs.normalizer import (
    ACCOUNT_PATH_NIBBLES,
    MAX_ACCOUNT_NODE_BYTES,
    MAX_ACCOUNT_PROOF_NODES,
    MAX_LEAF_PATH_NIBBLES,
    compute_leaf_value_commitment,
    hex_to_bytes,
)
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.base import ProofStatement


ACCOUNT_INCLUSION_VERIFICATION_METADATA = {
    "branch_child_binding": "in_circuit",
    "leaf_account_binding": "in_circuit_or_partial",
    "rlp_decoding": "python_preprocessed",
    "mpt_verification_level": "bounded_normalized_mpt",
}


class AccountInclusionStatement(ProofStatement):
    name = "account_inclusion"

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        baseline = baseline_results[0]
        if not baseline.ok or baseline.leaf is None:
            raise ValueError(
                f"Baseline verification failed for account inclusion: {baseline.error}"
            )

        bounded_ok, bounded_error = bounded_account_precheck(payload)
        if not bounded_ok:
            raise ValueError(f"Bounded proof precheck failed: {bounded_error}")

        proof_nodes = [hex_to_bytes(node_hex) for node_hex in payload.account_proof]

        decoded_nodes = [rlp.decode(node) for node in proof_nodes]
        expected_shapes = [17, 17, 17, 2]
        node_shapes = [len(node) if isinstance(node, list) else -1 for node in decoded_nodes]
        if node_shapes != expected_shapes:
            raise ValueError(f"Unsupported proof node shape sequence: {node_shapes}")

        hash_name = baseline.hash_name.lower()
        if hash_name == "keccak256":
            hash_variant = Keccak256Hash()
            hash_variant_id = 1
        elif hash_name == "poseidon2":
            hash_variant = Poseidon2Hash.from_environment()
            hash_variant_id = 2
        else:
            raise ValueError(f"Unsupported hash variant for account inclusion: {hash_name}")

        address_bytes = hex_to_bytes(payload.address)
        if len(address_bytes) != 20:
            raise ValueError("Account address must be 20 bytes.")

        path_nibbles = bytes_to_nibbles(hash_variant.digest(address_bytes))
        if len(path_nibbles) != ACCOUNT_PATH_NIBBLES:
            raise ValueError(
                f"Expected account path of {ACCOUNT_PATH_NIBBLES} nibbles, got {len(path_nibbles)}"
            )

        branch_child_indices: list[int] = []
        branch_child_hashes_hex: list[str] = []
        branch_children_hex: list[list[str]] = []
        path_index = 0
        for node_idx in range(3):
            node = decoded_nodes[node_idx]
            if not isinstance(node, list) or len(node) != 17:
                raise ValueError(f"Expected branch node at index {node_idx}")

            branch_children_for_node: list[str] = []
            for slot in range(16):
                slot_child = node[slot]
                if not isinstance(slot_child, (bytes, bytearray)):
                    raise ValueError(
                        f"Branch child at node {node_idx}, slot {slot} is not bytes."
                    )
                slot_child_bytes = bytes(slot_child)
                if len(slot_child_bytes) == 0:
                    slot_child_hash = b"\x00" * 32
                elif len(slot_child_bytes) < 32:
                    slot_child_hash = hash_variant.digest(slot_child_bytes)
                elif len(slot_child_bytes) == 32:
                    slot_child_hash = slot_child_bytes
                else:
                    raise ValueError(
                        f"Unexpected branch child length {len(slot_child_bytes)} at node {node_idx}, slot {slot}."
                    )
                branch_children_for_node.append("0x" + slot_child_hash.hex())

            nibble = path_nibbles[path_index]
            child = node[nibble]
            if not isinstance(child, (bytes, bytearray)) or len(child) == 0:
                raise ValueError(f"Branch child missing at node {node_idx}, nibble {nibble}")
            child_bytes = bytes(child)
            child_hash = (
                hash_variant.digest(child_bytes) if len(child_bytes) < 32 else child_bytes
            )
            if len(child_hash) != 32:
                raise ValueError("Expected 32-byte child hash for branch linkage.")
            branch_child_indices.append(nibble)
            branch_child_hashes_hex.append("0x" + child_hash.hex())
            branch_children_hex.append(branch_children_for_node)
            path_index += 1

        leaf_node = decoded_nodes[3]
        if not isinstance(leaf_node, list) or len(leaf_node) != 2:
            raise ValueError("Expected terminal leaf node at index 3.")
        compact_path = leaf_node[0]
        if not isinstance(compact_path, (bytes, bytearray)):
            raise ValueError("Leaf compact path is not bytes.")
        leaf_path_nibbles, is_leaf = decode_compact_with_flags(bytes(compact_path))
        if not is_leaf:
            raise ValueError("Expected leaf node flag in terminal node.")
        if leaf_path_nibbles != path_nibbles[path_index : path_index + len(leaf_path_nibbles)]:
            raise ValueError("Leaf path nibbles do not match hashed account path.")
        if path_index + len(leaf_path_nibbles) != len(path_nibbles):
            raise ValueError("Leaf path does not consume full hashed account path.")
        if len(leaf_path_nibbles) > MAX_LEAF_PATH_NIBBLES:
            raise ValueError(
                f"Leaf path length {len(leaf_path_nibbles)} exceeds {MAX_LEAF_PATH_NIBBLES}"
            )

        storage_root_bytes = hex_to_bytes(baseline.leaf.storage_root)
        code_hash_bytes = hex_to_bytes(baseline.leaf.code_hash)
        if len(storage_root_bytes) != 32 or len(code_hash_bytes) != 32:
            raise ValueError("Decoded storageRoot/codeHash must be 32 bytes each.")

        leaf_value_commitment = compute_leaf_value_commitment(
            baseline.leaf.nonce,
            baseline.leaf.balance,
            storage_root_bytes,
            code_hash_bytes,
        )

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "state_root": baseline.state_root,
                "account_address": payload.address,
                "hash_name": hash_name,
                "hash_variant_id": hash_variant_id,
                "leaf_value_commitment": leaf_value_commitment,
            },
            private_inputs={
                "node_rlp_hexes": payload.account_proof,
                "node_rlp_lens": [len(node) for node in proof_nodes],
                "node_kinds": [0, 0, 0, 2],
                "branch_child_indices": branch_child_indices,
                "branch_child_hashes": branch_child_hashes_hex,
                "branch_children": branch_children_hex,
                "path_nibbles": path_nibbles,
                "leaf_path_nibbles": leaf_path_nibbles,
                "leaf_path_len": len(leaf_path_nibbles),
                "nonce": baseline.leaf.nonce,
                "balance": baseline.leaf.balance,
                "storage_root": baseline.leaf.storage_root,
                "code_hash": baseline.leaf.code_hash,
            },
            metadata={
                "source_file": payload.source_file,
                "source_index": payload.source_index,
                "block_number": payload.block_number,
                "proof_mode": "baseline_verified_account_inclusion_bounded",
                **ACCOUNT_INCLUSION_VERIFICATION_METADATA,
                "bounds": {
                    "max_account_proof_nodes": MAX_ACCOUNT_PROOF_NODES,
                    "max_account_node_bytes": MAX_ACCOUNT_NODE_BYTES,
                    "max_leaf_path_nibbles": MAX_LEAF_PATH_NIBBLES,
                },
            },
        )
