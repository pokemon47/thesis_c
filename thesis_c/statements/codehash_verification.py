from __future__ import annotations

from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.base import ProofStatement


class CodeHashVerificationStatement(ProofStatement):
    name = "codehash_verification"

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        baseline = baseline_results[0]
        if not baseline.ok or baseline.leaf is None:
            raise ValueError(
                f"Baseline verification failed for codeHash verification: {baseline.error}"
            )

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "address": payload.address,
                "state_root": baseline.state_root,
                "expected_code_hash": payload.code_hash.lower(),
                "hash_name": baseline.hash_name,
            },
            private_inputs={
                "decoded_code_hash": baseline.leaf.code_hash.lower(),
                "account_leaf_rlp": baseline.leaf.rlp_hex,
                "account_proof": payload.account_proof,
            },
            metadata={
                "source_file": payload.source_file,
                "source_index": payload.source_index,
                "block_number": payload.block_number,
            },
        )
