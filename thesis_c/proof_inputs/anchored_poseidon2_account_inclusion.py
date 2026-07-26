from __future__ import annotations

from dataclasses import asdict
from typing import Any

from thesis_c.proof_inputs.header_anchor import (
    HeaderAnchorFixture,
    build_header_anchor_witness,
    validate_header_fixture,
)
from thesis_c.proof_inputs.expanded_account_witness import build_poseidon2_account_inclusion_witness
from thesis_c.proof_inputs.normalizer import hex_to_u8_list, pad_u8_list

_ANCHOR_HEADER_KEYS = {
    "header_anchor",
    "headerAnchor",
    "anchored_header",
}


def header_anchor_fixture_from_result(result: dict[str, Any]) -> HeaderAnchorFixture:
    header_anchor: Any = result
    if not (isinstance(result, dict) and {"fixture_id", "raw_header_rlp", "block_hash"} <= result.keys()):
        header_anchor = None
        for key in _ANCHOR_HEADER_KEYS:
            if key in result:
                header_anchor = result[key]
                break
    if not isinstance(header_anchor, dict):
        raise ValueError("Anchored account proof payload is missing header_anchor metadata.")

    fixture = HeaderAnchorFixture(
        fixture_id=str(header_anchor["fixture_id"]),
        network=str(header_anchor["network"]),
        chain_id=int(header_anchor["chain_id"]),
        block_number=int(header_anchor["block_number"]),
        block_hash=str(header_anchor["block_hash"]),
        state_root=str(header_anchor["state_root"]),
        raw_header_rlp=str(header_anchor["raw_header_rlp"]),
        header_rlp_len=int(header_anchor["header_rlp_len"]),
        header_field_count=int(header_anchor["header_field_count"]),
        header_rlp_source=str(header_anchor["header_rlp_source"]),
        header_hash_function=str(header_anchor["header_hash_function"]),
        source_reference=str(header_anchor["source_reference"]),
        reconstructed_header_fields=[
            str(item) for item in header_anchor["reconstructed_header_fields"]
        ],
    )
    validation = validate_header_fixture(fixture)
    if validation.error is not None or not validation.header_ready:
        raise ValueError(
            f"Anchored header fixture {fixture.fixture_id} failed validation: "
            f"hash_matches={validation.header_hash_matches}, "
            f"state_root_matches={validation.state_root_matches}, error={validation.error}"
        )
    return fixture


def build_anchored_poseidon2_account_inclusion_witness(
    public_inputs: dict[str, Any],
    private_inputs: dict[str, Any],
) -> dict[str, Any]:
    account_public_inputs = {
        "state_root": public_inputs["state_root"],
        "account_address": public_inputs["account_address"],
        "hash_name": "poseidon2",
        "hash_variant_id": public_inputs["hash_variant_id"],
        "leaf_value_commitment": 0,
    }

    header_witness = build_header_anchor_witness(
        header_anchor_fixture_from_result(private_inputs["header_anchor"])
    )
    if header_witness["public_expected_state_root"] != hex_to_u8_list(
        str(public_inputs["state_root"])
    ):
        raise ValueError(
            "Anchored header state root does not match the authenticated account state root."
        )

    account_private_inputs = {
        key: value
        for key, value in private_inputs.items()
        if key not in _ANCHOR_HEADER_KEYS
        and key not in {
            "header_witness_version",
            "private_header_bytes",
            "private_header_len",
        }
    }
    account_witness = build_poseidon2_account_inclusion_witness(
        account_public_inputs,
        account_private_inputs,
        retain_terminal_layout_fields=True,
    )

    witness = {
        "public_block_hash": pad_u8_list(
            hex_to_u8_list(str(public_inputs["block_hash"])),
            32,
        ),
        "public_state_root": account_witness.pop("public_state_root"),
        "public_state_root_field": account_witness.pop("public_state_root_field"),
        "public_account_address": account_witness.pop("public_account_address"),
        "public_hash_variant_id": account_witness.pop("public_hash_variant_id"),
        "header_witness_version": header_witness["witness_version"],
        "private_header_bytes": header_witness["private_header_bytes"],
        "private_header_len": header_witness["private_header_len"],
        "account_witness_version": account_witness.pop("witness_version"),
    }
    witness.update(account_witness)
    return witness
