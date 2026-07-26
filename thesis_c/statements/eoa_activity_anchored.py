from __future__ import annotations

from thesis_c.proof_inputs.anchored_eoa_activity import build_anchored_header_inputs
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.base import ProofStatement
from thesis_c.statements.eoa_activity import EoaActivityStatement


def _state_root_field(state_root: str) -> int:
    return int(state_root[2:] if state_root.startswith("0x") else state_root, 16)


def _prepare_anchored_eoa_activity(
    *,
    name: str,
    hash_name: str,
    payloads,
    baseline_results,
    allow_synthetic: bool = False,
) -> PreparedStatement:
    if len(payloads) < 2 or len(baseline_results) < 2:
        raise ValueError("Anchored EOA activity requires two payloads.")

    eoa_prepared = EoaActivityStatement().prepare(payloads, baseline_results)
    if str(eoa_prepared.public_inputs["hash_name"]).lower() != hash_name:
        raise ValueError(f"Anchored EOA activity currently supports {hash_name} only.")

    first_baseline = baseline_results[0]
    second_baseline = baseline_results[1]
    if (
        first_baseline.leaf is None
        or second_baseline.leaf is None
        or first_baseline.leaf.nonce == second_baseline.leaf.nonce
    ):
        raise ValueError("Anchored EOA activity requires authenticated nonce inequality.")

    state_1 = build_anchored_header_inputs(
        state_root=str(eoa_prepared.public_inputs["state_root_1"]),
        block_number=payloads[0].block_number,
        fixture_id_suffix="state_1",
        source_reference=payloads[0].source_file,
        allow_synthetic=allow_synthetic,
    )
    state_2 = build_anchored_header_inputs(
        state_root=str(eoa_prepared.public_inputs["state_root_2"]),
        block_number=payloads[1].block_number,
        fixture_id_suffix="state_2",
        source_reference=payloads[1].source_file,
        allow_synthetic=allow_synthetic,
    )

    public_inputs = {
        "hash_name": eoa_prepared.public_inputs["hash_name"],
        "hash_variant_id": eoa_prepared.public_inputs["hash_variant_id"],
        "account_address": eoa_prepared.public_inputs["account_address"],
        "block_hash_1": state_1["header_anchor"]["block_hash"],
        "state_root_1": eoa_prepared.public_inputs["state_root_1"],
        "block_hash_2": state_2["header_anchor"]["block_hash"],
        "state_root_2": eoa_prepared.public_inputs["state_root_2"],
    }
    if hash_name == "poseidon2":
        public_inputs["state_root_1_field"] = _state_root_field(
            str(eoa_prepared.public_inputs["state_root_1"])
        )
        public_inputs["state_root_2_field"] = _state_root_field(
            str(eoa_prepared.public_inputs["state_root_2"])
        )

    private_inputs = {
        **eoa_prepared.private_inputs,
        "header_anchor_1": state_1["header_anchor"],
        "header_anchor_2": state_2["header_anchor"],
        "header_fixture_classification_1": state_1["header_fixture_classification"],
        "header_fixture_classification_2": state_2["header_fixture_classification"],
        "header_witness_version_1": state_1["header_witness_version"],
        "header_witness_version_2": state_2["header_witness_version"],
        "private_header_bytes_1": state_1["private_header_bytes"],
        "private_header_bytes_2": state_2["private_header_bytes"],
        "private_header_len_1": state_1["private_header_len"],
        "private_header_len_2": state_2["private_header_len"],
    }

    return PreparedStatement(
        statement_name=name,
        public_inputs=public_inputs,
        private_inputs=private_inputs,
        metadata={
            "source_file_1": payloads[0].source_file,
            "source_index_1": payloads[0].source_index,
            "source_file_2": payloads[1].source_file,
            "source_index_2": payloads[1].source_index,
            "block_number_1": payloads[0].block_number,
            "block_number_2": payloads[1].block_number,
            "proof_mode": f"baseline_verified_anchored_eoa_activity_{hash_name}_two_state",
            "header_block_number_1": state_1["header_anchor"]["block_number"],
            "header_block_number_2": state_2["header_anchor"]["block_number"],
            "header_block_hash_1": state_1["header_anchor"]["block_hash"],
            "header_block_hash_2": state_2["header_anchor"]["block_hash"],
            "header_state_root_1": state_1["header_anchor"]["state_root"],
            "header_state_root_2": state_2["header_anchor"]["state_root"],
            "header_rlp_len_1": state_1["header_anchor"]["header_rlp_len"],
            "header_rlp_len_2": state_2["header_anchor"]["header_rlp_len"],
            "header_field_count_1": state_1["header_anchor"]["header_field_count"],
            "header_field_count_2": state_2["header_anchor"]["header_field_count"],
            "header_rlp_source_1": state_1["header_anchor"]["header_rlp_source"],
            "header_rlp_source_2": state_2["header_anchor"]["header_rlp_source"],
            "header_hash_function_1": state_1["header_anchor"]["header_hash_function"],
            "header_hash_function_2": state_2["header_anchor"]["header_hash_function"],
            "header_source_reference_1": state_1["header_anchor"]["source_reference"],
            "header_source_reference_2": state_2["header_anchor"]["source_reference"],
            "header_fixture_classification_1": state_1["header_fixture_classification"],
            "header_fixture_classification_2": state_2["header_fixture_classification"],
            "authenticated_nonce_1": first_baseline.leaf.nonce,
            "authenticated_nonce_2": second_baseline.leaf.nonce,
            "authenticated_code_hash_1": first_baseline.leaf.code_hash,
            "authenticated_code_hash_2": second_baseline.leaf.code_hash,
            "eoa_condition": "narrow_non_delegated_empty_code_hash",
            "bounds": {
                "header_witness_version": 1,
            },
        },
    )


class AnchoredEoaActivityStatement(ProofStatement):
    name = "eoa_activity_anchored"
    required_payloads = 2

    def prepare(
        self,
        payloads,
        baseline_results,
        *,
        allow_synthetic: bool = False,
    ) -> PreparedStatement:
        return _prepare_anchored_eoa_activity(
            name=self.name,
            hash_name="keccak256",
            payloads=payloads,
            baseline_results=baseline_results,
            allow_synthetic=allow_synthetic,
        )

    def prepare_with_synthetic_headers(self, payloads, baseline_results) -> PreparedStatement:
        return self.prepare(payloads, baseline_results, allow_synthetic=True)


class AnchoredPoseidon2EoaActivityStatement(ProofStatement):
    name = "eoa_activity_anchored_poseidon2"
    required_payloads = 2

    def prepare(
        self,
        payloads,
        baseline_results,
        *,
        allow_synthetic: bool = False,
    ) -> PreparedStatement:
        return _prepare_anchored_eoa_activity(
            name=self.name,
            hash_name="poseidon2",
            payloads=payloads,
            baseline_results=baseline_results,
            allow_synthetic=allow_synthetic,
        )

    def prepare_with_synthetic_headers(self, payloads, baseline_results) -> PreparedStatement:
        return self.prepare(payloads, baseline_results, allow_synthetic=True)
