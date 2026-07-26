from __future__ import annotations

from dataclasses import asdict

from thesis_c.baseline.account_verifier import variable_depth_account_precheck
from thesis_c.baseline.verifier_adapter import hex_to_bytes
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.proof_inputs.normalizer import (
    compute_leaf_value_commitment,
    MAX_ACCOUNT_NODE_BYTES,
    MAX_ACCOUNT_PROOF_NODES,
    MAX_LEAF_PATH_NIBBLES,
)
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.base import ProofStatement


ACCOUNT_INCLUSION_VERIFICATION_METADATA = {
    "branch_child_binding": "in_circuit",
    "leaf_account_binding": "in_circuit_or_partial",
    "rlp_decoding": "python_preprocessed",
    "mpt_verification_level": "bounded_variable_depth_mpt",
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

        hash_name = baseline.hash_name.lower()
        if hash_name == "keccak256":
            hash_variant = Keccak256Hash()
            hash_variant_id = 1
        elif hash_name == "poseidon2":
            hash_variant = Poseidon2Hash.from_environment()
            hash_variant_id = 2
        else:
            raise ValueError(f"Unsupported hash variant for account inclusion: {hash_name}")

        authenticated = variable_depth_account_precheck(payload, hash_variant)
        address_bytes = hex_to_bytes(payload.address)

        private_inputs = {
            "node_rlp_hexes": payload.account_proof,
            "node_rlp_lens": list(authenticated.node_lens),
            "node_kinds": list(authenticated.node_kinds),
            "branch_child_indices": list(authenticated.branch_child_indices),
            "branch_child_hashes": [
                "0x" + item.hex() for item in authenticated.branch_child_hashes
            ],
            "branch_children": [
                ["0x" + item.hex() for item in branch]
                for branch in authenticated.branch_children
            ],
            "address_hash": "0x" + hash_variant.digest(address_bytes).hex(),
            "path_nibbles": list(authenticated.path_nibbles),
            "leaf_path_nibbles": list(authenticated.leaf_path_nibbles),
            "leaf_path_len": len(authenticated.leaf_path_nibbles),
            "account_proof_depth": authenticated.active_depth,
            "leaf_layout": asdict(authenticated.leaf_layout),
            "account_value_layout": asdict(authenticated.account_layout),
        }

        public_inputs = {
            "state_root": baseline.state_root,
            "account_address": payload.address,
            "hash_name": hash_name,
            "hash_variant_id": hash_variant_id,
        }
        if hash_name == "keccak256":
            public_inputs["leaf_value_commitment"] = compute_leaf_value_commitment(
                baseline.leaf.nonce,
                baseline.leaf.balance,
                hex_to_bytes(baseline.leaf.storage_root),
                hex_to_bytes(baseline.leaf.code_hash),
            )

        return PreparedStatement(
            statement_name=self.name,
            public_inputs=public_inputs,
            private_inputs=private_inputs,
            metadata={
                "source_file": payload.source_file,
                "source_index": payload.source_index,
                "block_number": payload.block_number,
                "proof_mode": "baseline_verified_account_inclusion_variable_depth",
                **ACCOUNT_INCLUSION_VERIFICATION_METADATA,
                "bounds": {
                    "max_account_proof_nodes": MAX_ACCOUNT_PROOF_NODES,
                    "max_account_node_bytes": MAX_ACCOUNT_NODE_BYTES,
                    "max_leaf_path_nibbles": MAX_LEAF_PATH_NIBBLES,
                },
            },
        )
