from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

import pytest

from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.proof_inputs.block_context import parse_block_context
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.statements.eoa_activity import EMPTY_CODE_HASH, EoaActivityStatement


KECCAK_FOREST = Path("/Users/doodleaks/Developer/Thesis/sample_proofs/proof_keccak_forest.json")
KECCAK_SLICE = Path("/Users/doodleaks/Developer/Thesis/sample_proofs/proof_keccak_slice.json")
EOA_FIXTURES = Path(__file__).parent / "fixtures" / "datasets" / "eoa_activity"


def _payloads_and_baselines():
    payloads = [load_proof_path(KECCAK_FOREST)[0], load_proof_path(KECCAK_SLICE)[0]]
    baselines = [verify_account_payload(payload, Keccak256Hash()) for payload in payloads]
    return payloads, baselines


def test_prepares_two_valid_same_address_empty_codehash_payloads() -> None:
    payloads, baselines = _payloads_and_baselines()

    prepared = EoaActivityStatement().prepare(payloads, baselines)

    assert prepared.statement_name == "eoa_activity"
    assert prepared.public_inputs["account_address"].lower() == payloads[0].address.lower()
    assert prepared.metadata["eoa_condition"] == "narrow_non_delegated_empty_code_hash"
    assert prepared.metadata["decoded_code_hash_1"] == EMPTY_CODE_HASH
    assert prepared.metadata["decoded_code_hash_2"] == EMPTY_CODE_HASH
    assert "nonce" not in prepared.private_inputs["state_1"]
    assert "code_hash" not in prepared.private_inputs["state_1"]


def test_equal_nonce_pair_reaches_noir_mapping_for_circuit_failure() -> None:
    payloads, baselines = _payloads_and_baselines()
    assert prepared_nonce_pair_is_equal(baselines)

    prepared = EoaActivityStatement().prepare(payloads, baselines)
    noir_inputs = to_noir_input_map(prepared)

    assert noir_inputs["public_hash_variant_id"] == 1
    assert "private_account_nonce_layout_1" in noir_inputs
    assert "private_account_nonce_layout_2" in noir_inputs
    assert "private_decoded_nonce_1" not in noir_inputs
    assert "private_code_hash_1" not in noir_inputs


def test_different_addresses_fail_input_hygiene() -> None:
    payloads, baselines = _payloads_and_baselines()
    payloads[1] = replace(payloads[1], address="0x" + "12" * 20)

    with pytest.raises(ValueError, match="same account address"):
        EoaActivityStatement().prepare(payloads, baselines)


def test_wrong_public_address_test_path_reaches_noir_mapping() -> None:
    payloads, baselines = _payloads_and_baselines()

    prepared = EoaActivityStatement(
        public_account_address_override="0x" + "12" * 20,
    ).prepare(payloads, baselines)
    noir_inputs = to_noir_input_map(prepared)

    assert noir_inputs["public_account_address"] == [0x12] * 20


def test_block_context_absent_is_backward_compatible() -> None:
    context = parse_block_context(None)

    assert context.header_rlp_source == "absent"
    assert context.validation.header_ready is False


def test_block_context_records_source_exported_header_validation_results() -> None:
    context = parse_block_context(
        {
            "rawHeaderRlp": "0xc0",
            "blockHash": "0x" + "00" * 32,
            "stateRoot": "0x" + "11" * 32,
            "provenance": {"besuVersion": "test-besu", "generationCommand": "export"},
        }
    )

    assert context.header_rlp_source == "source_exported"
    assert context.validation.header_ready is False
    assert context.validation.error is not None
    assert context.provenance.besu_version == "test-besu"


def test_eoa_fixture_inventory_marks_current_pairs_as_synthetic_only() -> None:
    fixtures = sorted(EOA_FIXTURES.glob("*.json"))
    assert {path.name for path in fixtures} == {
        "synthetic_keccak_eoa_activity_pair.json",
        "synthetic_keccak_nonempty_codehash_pair.json",
        "synthetic_poseidon2_eoa_activity_pair.json",
    }

    inventory = []
    for path in fixtures:
        payload = json.loads(path.read_text())
        states = payload if isinstance(payload, list) else payload.get("states", [])
        results = [state["result"] for state in states]
        addresses = {result["address"].lower() for result in results}
        roots = {result.get("stateRoot") for result in results}
        code_hashes = {result.get("codeHash", "").lower() for result in results}
        nonces = [result.get("nonce") for result in results]
        inventory.append(
            {
                "name": path.name,
                "synthetic": bool(payload.get("synthetic_fixture", False))
                if isinstance(payload, dict)
                else path.name.startswith("synthetic_")
                and all(
                    result.get("syntheticFixture", True) for result in results
                ),
                "same_address": len(addresses) == 1,
                "distinct_roots": len(roots) == len(states),
                "empty_code_hash": code_hashes == {EMPTY_CODE_HASH},
                "different_nonce": len(set(nonces)) == len(nonces),
            }
        )

    assert all(item["synthetic"] for item in inventory)
    assert all(item["same_address"] for item in inventory)
    assert all(item["distinct_roots"] for item in inventory)
    assert all(item["different_nonce"] for item in inventory if "nonempty" not in item["name"])
    assert not next(item for item in inventory if "nonempty" in item["name"])["empty_code_hash"]


def test_no_real_paired_eoa_dataset_is_present_in_fixture_inventory() -> None:
    for path in EOA_FIXTURES.glob("*.json"):
        payload = json.loads(path.read_text())
        states = payload if isinstance(payload, list) else payload.get("states", [])
        assert states
        assert path.name.startswith("synthetic_")


def prepared_nonce_pair_is_equal(baselines) -> bool:
    return baselines[0].leaf is not None and baselines[1].leaf is not None and (
        baselines[0].leaf.nonce == baselines[1].leaf.nonce
    )
