from __future__ import annotations

from dataclasses import asdict

from thesis_c.baseline.account_layout import (
    encoded_slice,
    parse_nested_account_layout,
    payload_slice,
)
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.proof_inputs.normalizer import hex_to_bytes
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.statements.base import ProofStatement


EMPTY_CODE_HASH = "0x" + Keccak256Hash().digest(b"").hex()


class EoaActivityStatement(ProofStatement):
    name = "eoa_activity"
    required_payloads = 2

    def __init__(
        self,
        *,
        public_account_address_override: str | None = None,
        public_state_root_1_override: str | None = None,
        public_state_root_2_override: str | None = None,
        hash_variant_id_override: int | None = None,
        allow_mismatched_address_for_testing: bool = False,
        allow_non_empty_code_hash_for_testing: bool = False,
    ) -> None:
        self.public_account_address_override = public_account_address_override
        self.public_state_root_1_override = public_state_root_1_override
        self.public_state_root_2_override = public_state_root_2_override
        self.hash_variant_id_override = hash_variant_id_override
        self.allow_mismatched_address_for_testing = allow_mismatched_address_for_testing
        self.allow_non_empty_code_hash_for_testing = allow_non_empty_code_hash_for_testing

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        if len(payloads) < 2 or len(baseline_results) < 2:
            raise ValueError("EOA activity statement requires two payloads.")

        state_inputs: list[dict] = []
        account_prepared: list[PreparedStatement] = []
        decoded_code_hashes: list[str] = []
        nonce_encodings: list[str] = []

        first_payload, second_payload = payloads[:2]
        if (
            first_payload.address.lower() != second_payload.address.lower()
            and not self.allow_mismatched_address_for_testing
        ):
            raise ValueError("EOA activity requires the same account address in both proofs.")

        for idx, (payload, baseline) in enumerate(
            zip(payloads[:2], baseline_results[:2], strict=True),
            start=1,
        ):
            if not baseline.ok or baseline.leaf is None:
                raise ValueError(
                    f"Baseline verification failed for EOA payload {idx}: {baseline.error}"
                )

            prepared = AccountInclusionStatement().prepare([payload], [baseline])
            leaf_node_rlp = hex_to_bytes(payload.account_proof[-1])
            leaf_layout, account_layout = parse_nested_account_layout(leaf_node_rlp)

            layout_code_hash = "0x" + payload_slice(
                leaf_node_rlp,
                account_layout.code_hash,
            ).hex()
            if layout_code_hash.lower() != baseline.leaf.code_hash.lower():
                raise ValueError(
                    f"EOA payload {idx} codeHash layout does not match decoded account leaf."
                )
            if (
                layout_code_hash.lower() != EMPTY_CODE_HASH
                and not self.allow_non_empty_code_hash_for_testing
            ):
                raise ValueError(
                    "EOA activity currently supports only the narrow non-delegated "
                    "empty-codeHash condition."
                )

            account_private_inputs = {
                key: value
                for key, value in prepared.private_inputs.items()
                if key not in {"nonce", "balance", "storage_root", "code_hash"}
            }
            state_inputs.append(
                {
                    **account_private_inputs,
                    "leaf_layout": {
                        "outer_list": asdict(leaf_layout.outer_list),
                        "compact_path_item": asdict(leaf_layout.compact_path_item),
                        "account_value_item": asdict(leaf_layout.account_value_item),
                    },
                    "account_value_layout": {
                        "inner_list": asdict(account_layout.inner_list),
                        "nonce": asdict(account_layout.nonce),
                        "balance": asdict(account_layout.balance),
                        "storage_root": asdict(account_layout.storage_root),
                        "code_hash": asdict(account_layout.code_hash),
                    },
                }
            )
            account_prepared.append(prepared)
            decoded_code_hashes.append(layout_code_hash)
            nonce_encodings.append("0x" + encoded_slice(leaf_node_rlp, account_layout.nonce).hex())

        first_public = account_prepared[0].public_inputs
        second_public = account_prepared[1].public_inputs
        hash_name = str(first_public["hash_name"]).lower()
        if str(second_public["hash_name"]).lower() != hash_name:
            raise ValueError("EOA activity requires both states to use the same hash variant.")

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "hash_name": hash_name,
                "hash_variant_id": (
                    self.hash_variant_id_override
                    if self.hash_variant_id_override is not None
                    else first_public["hash_variant_id"]
                ),
                "account_address": (
                    self.public_account_address_override
                    if self.public_account_address_override is not None
                    else first_public["account_address"]
                ),
                "state_root_1": (
                    self.public_state_root_1_override
                    if self.public_state_root_1_override is not None
                    else first_public["state_root"]
                ),
                "state_root_2": (
                    self.public_state_root_2_override
                    if self.public_state_root_2_override is not None
                    else second_public["state_root"]
                ),
            },
            private_inputs={
                "state_1": state_inputs[0],
                "state_2": state_inputs[1],
            },
            metadata={
                "source_file_1": first_payload.source_file,
                "source_index_1": first_payload.source_index,
                "source_file_2": second_payload.source_file,
                "source_index_2": second_payload.source_index,
                "block_number_1": first_payload.block_number,
                "block_number_2": second_payload.block_number,
                "proof_mode": "baseline_verified_eoa_activity_variable_depth_supplied_roots",
                "account_proof_depth_1": account_prepared[0].private_inputs["account_proof_depth"],
                "account_proof_depth_2": account_prepared[1].private_inputs["account_proof_depth"],
                "eoa_condition": "narrow_non_delegated_empty_code_hash",
                "eip_7702_delegation_indicator_code": "out_of_scope",
                "decoded_code_hash_1": decoded_code_hashes[0],
                "decoded_code_hash_2": decoded_code_hashes[1],
                "nonce_encoding_1": nonce_encodings[0],
                "nonce_encoding_2": nonce_encodings[1],
                "allow_mismatched_address_for_testing": self.allow_mismatched_address_for_testing,
                "allow_non_empty_code_hash_for_testing": self.allow_non_empty_code_hash_for_testing,
            },
        )
