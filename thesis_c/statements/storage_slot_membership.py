from __future__ import annotations

from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.base import ProofStatement


class StorageSlotMembershipStatement(ProofStatement):
    name = "storage_slot_membership"

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        baseline = baseline_results[0]
        if not baseline.ok or baseline.leaf is None:
            raise ValueError(
                f"Baseline verification failed for storage slot membership: {baseline.error}"
            )
        if not payload.storage_proof:
            raise ValueError("Storage slot membership requires storageProof entries.")

        first_entry = payload.storage_proof[0]
        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "address": payload.address,
                "state_root": baseline.state_root,
                "storage_root": baseline.leaf.storage_root,
                "slot_key": first_entry.key,
                "slot_value": first_entry.value,
                "hash_name": baseline.hash_name,
            },
            private_inputs={
                "account_proof": payload.account_proof,
                "storage_proof": first_entry.proof,
                "account_leaf_rlp": baseline.leaf.rlp_hex,
            },
            metadata={
                "source_file": payload.source_file,
                "source_index": payload.source_index,
                "block_number": payload.block_number,
            },
        )
