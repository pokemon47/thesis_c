from __future__ import annotations

from dataclasses import asdict

from thesis_c.baseline.account_layout import (
    assert_canonical_uint_rlp_item,
    encoded_slice,
    parse_nested_account_layout,
    parse_rpc_quantity,
    payload_slice,
    uint256_to_u64_limbs,
)
from thesis_c.proof_inputs.normalizer import hex_to_bytes
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.statements.base import ProofStatement


class BalanceVerificationStatement(ProofStatement):
    name = "balance_verification"

    def __init__(
        self,
        claimed_balance: int | str | None = None,
        *,
        allow_wrong_claim_for_testing: bool = False,
    ) -> None:
        self.claimed_balance = claimed_balance
        self.allow_wrong_claim_for_testing = allow_wrong_claim_for_testing

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        baseline = baseline_results[0]
        if not baseline.ok or baseline.leaf is None:
            raise ValueError(
                f"Baseline verification failed for balance verification: {baseline.error}"
            )

        claimed_balance = parse_rpc_quantity(
            payload.balance if self.claimed_balance is None else self.claimed_balance
        )
        claimed_balance_limbs = uint256_to_u64_limbs(claimed_balance)
        if (
            baseline.leaf.balance != claimed_balance
            and not self.allow_wrong_claim_for_testing
        ):
            raise ValueError(
                "Claimed balance does not match decoded account balance: "
                f"claimed {claimed_balance}, decoded {baseline.leaf.balance}."
            )

        account_prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
        leaf_node_rlp = hex_to_bytes(payload.account_proof[-1])
        leaf_layout, account_layout = parse_nested_account_layout(leaf_node_rlp)

        encoded_balance = encoded_slice(leaf_node_rlp, account_layout.balance)
        decoded_balance = assert_canonical_uint_rlp_item(encoded_balance)
        if decoded_balance != baseline.leaf.balance:
            raise ValueError(
                "Canonical balance layout does not match decoded account balance: "
                f"layout {decoded_balance}, decoded {baseline.leaf.balance}."
            )
        if payload_slice(leaf_node_rlp, account_layout.storage_root).hex() != baseline.leaf.storage_root[2:]:
            raise ValueError("Account layout storageRoot does not match decoded account leaf.")
        if payload_slice(leaf_node_rlp, account_layout.code_hash).hex() != baseline.leaf.code_hash[2:]:
            raise ValueError("Account layout codeHash does not match decoded account leaf.")

        account_private_inputs = {
            key: value
            for key, value in account_prepared.private_inputs.items()
            if key not in {"nonce", "balance", "storage_root", "code_hash"}
        }

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "state_root": account_prepared.public_inputs["state_root"],
                "account_address": account_prepared.public_inputs["account_address"],
                "claimed_balance_limbs": claimed_balance_limbs,
                "hash_name": account_prepared.public_inputs["hash_name"],
                "hash_variant_id": account_prepared.public_inputs["hash_variant_id"],
            },
            private_inputs={
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
            },
            metadata={
                "source_file": payload.source_file,
                "source_index": payload.source_index,
                "block_number": payload.block_number,
                "proof_mode": "baseline_verified_balance_verification_variable_depth",
                "claimed_balance_source": (
                    "payload" if self.claimed_balance is None else "explicit"
                ),
                "allow_wrong_claim_for_testing": self.allow_wrong_claim_for_testing,
            },
        )
