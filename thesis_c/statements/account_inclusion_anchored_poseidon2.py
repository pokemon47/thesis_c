from __future__ import annotations

from thesis_c.proof_inputs.anchored_poseidon2_account_inclusion import header_anchor_fixture_from_result
from thesis_c.proof_inputs.header_anchor import build_header_anchor_witness
from thesis_c.proof_inputs.normalizer import MAX_ACCOUNT_NODE_BYTES, MAX_ACCOUNT_PROOF_NODES, MAX_LEAF_PATH_NIBBLES
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.statements.base import ProofStatement


ANCHORED_ACCOUNT_INCLUSION_VERIFICATION_METADATA = {
    "block_hash_binding": "in_circuit",
    "header_authentication": "in_circuit",
    "header_state_root_binding": "in_circuit",
}


class AnchoredPoseidon2AccountInclusionStatement(ProofStatement):
    name = "account_inclusion_anchored_poseidon2"

    @staticmethod
    def _state_root_field(state_root: str) -> int:
        return int(state_root[2:] if state_root.startswith("0x") else state_root, 16)

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        baseline = baseline_results[0]
        if not baseline.ok or baseline.leaf is None:
            raise ValueError(
                f"Baseline verification failed for anchored Poseidon2 account inclusion: {baseline.error}"
            )

        account_prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
        if str(account_prepared.public_inputs["hash_name"]).lower() != "poseidon2":
            raise ValueError("Anchored Poseidon2 account inclusion currently supports poseidon2 only.")

        header_fixture = header_anchor_fixture_from_result(payload.raw_result)
        header_witness = build_header_anchor_witness(header_fixture)
        if header_fixture.state_root.lower() != str(account_prepared.public_inputs["state_root"]).lower():
            raise ValueError(
                "Anchored header state root does not match the authenticated account state root."
            )

        private_inputs = {
            **account_prepared.private_inputs,
            "header_anchor": {
                "fixture_id": header_fixture.fixture_id,
                "network": header_fixture.network,
                "chain_id": header_fixture.chain_id,
                "block_number": header_fixture.block_number,
                "block_hash": header_fixture.block_hash,
                "state_root": header_fixture.state_root,
                "raw_header_rlp": header_fixture.raw_header_rlp,
                "header_rlp_len": header_fixture.header_rlp_len,
                "header_field_count": header_fixture.header_field_count,
                "header_rlp_source": header_fixture.header_rlp_source,
                "header_hash_function": header_fixture.header_hash_function,
                "source_reference": header_fixture.source_reference,
                "reconstructed_header_fields": list(header_fixture.reconstructed_header_fields),
            },
            "header_witness_version": header_witness["witness_version"],
            "private_header_bytes": header_witness["private_header_bytes"],
            "private_header_len": header_witness["private_header_len"],
        }

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "block_hash": header_fixture.block_hash,
                "state_root": account_prepared.public_inputs["state_root"],
                "state_root_field": self._state_root_field(
                    str(account_prepared.public_inputs["state_root"])
                ),
                "account_address": account_prepared.public_inputs["account_address"],
                "hash_name": account_prepared.public_inputs["hash_name"],
                "hash_variant_id": account_prepared.public_inputs["hash_variant_id"],
            },
            private_inputs=private_inputs,
            metadata={
                "source_file": payload.source_file,
                "source_index": payload.source_index,
                "block_number": payload.block_number,
                "header_block_number": header_fixture.block_number,
                "header_block_hash": header_fixture.block_hash,
                "header_state_root": header_fixture.state_root,
                "header_rlp_len": header_fixture.header_rlp_len,
                "header_field_count": header_fixture.header_field_count,
                "header_rlp_source": header_fixture.header_rlp_source,
                "header_hash_function": header_fixture.header_hash_function,
                "header_source_reference": header_fixture.source_reference,
                "proof_mode": "baseline_verified_anchored_account_inclusion_poseidon2_variable_depth",
                "block_hash_binding": "in_circuit",
                "header_authentication": "in_circuit",
                **ANCHORED_ACCOUNT_INCLUSION_VERIFICATION_METADATA,
                "bounds": {
                    "max_account_proof_nodes": MAX_ACCOUNT_PROOF_NODES,
                    "max_account_node_bytes": MAX_ACCOUNT_NODE_BYTES,
                    "max_leaf_path_nibbles": MAX_LEAF_PATH_NIBBLES,
                },
            },
        )
