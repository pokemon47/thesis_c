from __future__ import annotations

from dataclasses import asdict

from thesis_c.baseline.account_layout import (
    parse_nested_account_layout,
    payload_slice,
)
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.proof_inputs.normalizer import hex_to_bytes
from thesis_c.proof_inputs.schema import PreparedStatement
from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.statements.base import ProofStatement


def parse_code_hash_bytes(value: str) -> bytes:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) != 64:
        raise ValueError("codeHash must be exactly 32 bytes.")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError("codeHash must be hex encoded.") from exc


class CodeHashVerificationStatement(ProofStatement):
    name = "codehash_verification"

    def __init__(
        self,
        expected_code_hash: str | None = None,
        *,
        allow_wrong_claim_for_testing: bool = False,
    ) -> None:
        self.expected_code_hash = expected_code_hash
        self.allow_wrong_claim_for_testing = allow_wrong_claim_for_testing

    def prepare(self, payloads, baseline_results) -> PreparedStatement:
        payload = payloads[0]
        baseline = baseline_results[0]
        if not baseline.ok or baseline.leaf is None:
            raise ValueError(
                f"Baseline verification failed for codeHash verification: {baseline.error}"
            )

        expected_code_hash = parse_code_hash_bytes(
            payload.code_hash if self.expected_code_hash is None else self.expected_code_hash
        )
        decoded_code_hash = parse_code_hash_bytes(baseline.leaf.code_hash)
        if (
            decoded_code_hash != expected_code_hash
            and not self.allow_wrong_claim_for_testing
        ):
            raise ValueError("Expected codeHash does not match decoded account codeHash.")

        account_prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
        leaf_node_rlp = hex_to_bytes(payload.account_proof[-1])
        leaf_layout, account_layout = parse_nested_account_layout(leaf_node_rlp)

        layout_code_hash = payload_slice(leaf_node_rlp, account_layout.code_hash)
        if len(layout_code_hash) != 32:
            raise ValueError("Account layout codeHash payload must be 32 bytes.")
        if layout_code_hash != decoded_code_hash:
            raise ValueError("Account layout codeHash does not match decoded account leaf.")

        account_private_inputs = {
            key: value
            for key, value in account_prepared.private_inputs.items()
            if key not in {"nonce", "balance", "storage_root", "code_hash"}
        }
        empty_code_hash = Keccak256Hash().digest(b"")
        code_hash_class = (
            "eoa_empty_code_hash"
            if decoded_code_hash == empty_code_hash
            else "contract_nonempty_code_hash"
        )

        return PreparedStatement(
            statement_name=self.name,
            public_inputs={
                "state_root": account_prepared.public_inputs["state_root"],
                "account_address": account_prepared.public_inputs["account_address"],
                "expected_code_hash": "0x" + expected_code_hash.hex(),
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
                "proof_mode": "baseline_verified_codehash_verification_variable_depth",
                "expected_code_hash_source": (
                    "payload" if self.expected_code_hash is None else "explicit"
                ),
                "allow_wrong_claim_for_testing": self.allow_wrong_claim_for_testing,
                "code_hash_class": code_hash_class,
            },
        )
