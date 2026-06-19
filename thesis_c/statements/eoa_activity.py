from __future__ import annotations

from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.base import ProofStatement


class EoaActivityStatement(ProofStatement):
    name = "eoa_activity"
    required_payloads = 2

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        if len(payloads) < 2 or len(baseline_results) < 2:
            raise ValueError("EOA activity statement requires two payloads.")

        first_payload, second_payload = payloads[:2]
        first_result, second_result = baseline_results[:2]

        for idx, result in enumerate((first_result, second_result), start=1):
            if not result.ok or result.leaf is None:
                raise ValueError(
                    f"Baseline verification failed for EOA payload {idx}: {result.error}"
                )

        if first_payload.address.lower() != second_payload.address.lower():
            raise ValueError("EOA activity requires the same account address in both proofs.")

        nonce_start = first_result.leaf.nonce
        nonce_end = second_result.leaf.nonce
        if nonce_end <= nonce_start:
            raise ValueError(
                f"EOA activity requires nonce increase, got {nonce_start} -> {nonce_end}."
            )

        block_start = first_payload.block_number
        block_end = second_payload.block_number
        if (
            block_start is not None
            and block_end is not None
            and block_end <= block_start
        ):
            raise ValueError(
                f"EOA activity requires block increase, got {block_start} -> {block_end}."
            )

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "address": first_payload.address,
                "nonce_start": nonce_start,
                "nonce_end": nonce_end,
                "block_start": block_start,
                "block_end": block_end,
                "hash_name": first_result.hash_name,
            },
            private_inputs={
                "state_root_start": first_result.state_root,
                "state_root_end": second_result.state_root,
                "account_leaf_start_rlp": first_result.leaf.rlp_hex,
                "account_leaf_end_rlp": second_result.leaf.rlp_hex,
                "account_proof_start": first_payload.account_proof,
                "account_proof_end": second_payload.account_proof,
            },
            metadata={
                "source_file_start": first_payload.source_file,
                "source_index_start": first_payload.source_index,
                "source_file_end": second_payload.source_file,
                "source_index_end": second_payload.source_index,
            },
        )
