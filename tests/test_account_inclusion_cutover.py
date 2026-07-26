from __future__ import annotations

from pathlib import Path

import pytest

from thesis_c.baseline.verifier_adapter import hex_to_bytes, verify_account_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.proof_inputs.normalizer import compute_leaf_value_commitment
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.statements.account_inclusion import AccountInclusionStatement


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _thesis_c_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _sample_keccak_proof_path() -> Path:
    return _repo_root() / "sample_proofs" / "proof_keccak_forest.json"


def _sample_poseidon2_proof_path() -> Path:
    return _thesis_c_root() / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json"


def test_keccak_account_inclusion_emits_canonical_layout_inputs() -> None:
    payloads = load_proof_path(_sample_keccak_proof_path())
    hash_variant = Keccak256Hash()
    baseline_results = [verify_account_payload(payload, hash_variant) for payload in payloads]
    prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
    noir_inputs = to_noir_input_map(prepared)

    assert prepared.public_inputs["hash_name"] == "keccak256"
    assert prepared.public_inputs["hash_variant_id"] == 1
    assert prepared.public_inputs["leaf_value_commitment"] == compute_leaf_value_commitment(
        baseline_results[0].leaf.nonce,
        baseline_results[0].leaf.balance,
        hex_to_bytes(baseline_results[0].leaf.storage_root),
        hex_to_bytes(baseline_results[0].leaf.code_hash),
    )
    assert "nonce" not in prepared.private_inputs
    assert "balance" not in prepared.private_inputs
    assert "storage_root" not in prepared.private_inputs
    assert "code_hash" not in prepared.private_inputs

    assert noir_inputs["witness_version"] == 1
    assert len(noir_inputs["public_state_root"]) == 32
    assert len(noir_inputs["public_account_address"]) == 20
    assert noir_inputs["public_hash_variant_id"] == 1
    assert noir_inputs["public_leaf_value_commitment"] == prepared.public_inputs["leaf_value_commitment"]
    assert len(noir_inputs["private_trie_key"]) == 32
    assert noir_inputs["private_active_node_count"] == prepared.private_inputs["account_proof_depth"]
    assert len(noir_inputs["private_node_bytes"]) == 16
    assert len(noir_inputs["private_node_lengths"]) == 16
    assert len(noir_inputs["private_node_kinds"]) == 16
    assert len(noir_inputs["private_node_list_layouts"]) == 16
    assert len(noir_inputs["private_node_item_layouts"]) == 16
    assert len(noir_inputs["private_node_compact_layouts"]) == 16
    assert len(noir_inputs["private_selected_ref_layouts"]) == 16
    assert len(noir_inputs["private_selected_ref_bytes"]) == 16
    assert len(noir_inputs["private_selected_ref_lengths"]) == 16
    assert len(noir_inputs["private_selected_ref_kinds"]) == 16
    assert len(noir_inputs["private_terminal_value"]) == 256
    assert noir_inputs["public_leaf_value_commitment"] == prepared.public_inputs["leaf_value_commitment"]
    assert "private_nonce" not in noir_inputs
    assert "private_balance" not in noir_inputs
    assert "private_storage_root" not in noir_inputs
    assert "private_code_hash" not in noir_inputs
    assert "private_node_rlp_bytes" not in noir_inputs
    assert "private_node_rlp_lens" not in noir_inputs
    assert "private_branch_child_indices" not in noir_inputs
    assert "private_branch_child_hashes" not in noir_inputs
    assert "private_branch_children" not in noir_inputs
    assert "private_leaf_outer_list_layout" in noir_inputs
    assert "private_leaf_compact_path_layout" in noir_inputs
    assert "private_leaf_account_value_layout" in noir_inputs
    assert "private_account_inner_list_layout" in noir_inputs
    assert "private_account_nonce_layout" in noir_inputs
    assert "private_account_balance_layout" in noir_inputs
    assert "private_account_storage_root_layout" in noir_inputs
    assert "private_account_code_hash_layout" in noir_inputs
    assert "public_state_root_field" not in noir_inputs


def test_poseidon2_account_inclusion_emits_parser_layout_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "THESIS_C_POSEIDON2_CMD",
        "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}",
    )

    payloads = load_proof_path(_sample_poseidon2_proof_path())
    hash_variant = Poseidon2Hash.from_environment()
    baseline_results = [verify_account_payload(payload, hash_variant) for payload in payloads]
    prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
    noir_inputs = to_noir_input_map(prepared)

    assert prepared.public_inputs["hash_name"] == "poseidon2"
    assert prepared.public_inputs["hash_variant_id"] == 2
    assert "leaf_value_commitment" not in prepared.public_inputs
    assert "nonce" not in prepared.private_inputs
    assert "balance" not in prepared.private_inputs
    assert "storage_root" not in prepared.private_inputs
    assert "code_hash" not in prepared.private_inputs

    assert "public_leaf_value_commitment" not in noir_inputs
    assert noir_inputs["witness_version"] == 1
    assert "public_state_root_field" in noir_inputs
    assert len(noir_inputs["public_state_root"]) == 32
    assert len(noir_inputs["public_account_address"]) == 20
    assert len(noir_inputs["private_trie_key"]) == 32
    assert noir_inputs["private_active_node_count"] == prepared.private_inputs["account_proof_depth"]
    assert len(noir_inputs["private_node_bytes"]) == 16
    assert len(noir_inputs["private_node_lengths"]) == 16
    assert len(noir_inputs["private_node_kinds"]) == 16
    assert len(noir_inputs["private_node_list_layouts"]) == 16
    assert len(noir_inputs["private_node_item_layouts"]) == 16
    assert len(noir_inputs["private_node_compact_layouts"]) == 16
    assert len(noir_inputs["private_selected_ref_layouts"]) == 16
    assert len(noir_inputs["private_selected_ref_bytes"]) == 16
    assert len(noir_inputs["private_selected_ref_lengths"]) == 16
    assert len(noir_inputs["private_selected_ref_kinds"]) == 16
    assert len(noir_inputs["private_terminal_value"]) == 256
    assert "private_branch_child_hash_fields" not in noir_inputs
    assert "private_branch_children_fields" not in noir_inputs
    assert "private_address_hash" not in noir_inputs


def test_poseidon2_expanded_account_verifier_remains_mechanically_synchronized() -> None:
    root = _thesis_c_root()
    standalone = (
        root
        / "circuits_mpt_inclusion_poseidon2"
        / "src"
        / "mpt_inclusion.nr"
    ).read_text()
    package_copy = (root / "circuits_poseidon2" / "src" / "mpt_inclusion.nr").read_text()
    normalized = package_copy.replace(
        "crate::expanded_hash_poseidon2::bytes32_to_field",
        "crate::hash_poseidon2::bytes32_to_field",
    ).replace(
        "crate::expanded_hash_poseidon2::hash_node",
        "crate::hash_poseidon2::hash_node",
    )

    assert normalized == standalone


def test_poseidon2_cutover_support_modules_remain_exact_copies() -> None:
    root = _thesis_c_root()
    copies = {
        "expanded_hash_poseidon2.nr": (
            root / "circuits_poseidon2" / "src" / "expanded_hash_poseidon2.nr",
            root / "circuits_mpt_inclusion_poseidon2" / "src" / "hash_poseidon2.nr",
        ),
        "expanded_mpt_capacity.nr": (
            root / "circuits_poseidon2" / "src" / "expanded_mpt_capacity.nr",
            root / "circuits_mpt_inclusion_poseidon2" / "src" / "expanded_mpt_capacity.nr",
        ),
    }

    for name, (current, authoritative) in copies.items():
        assert current.read_bytes() == authoritative.read_bytes(), name


def test_poseidon2_terminal_account_parser_core_matches_keccak_parser_core() -> None:
    root = _thesis_c_root()
    keccak = (root / "circuits" / "src" / "account_commitment.nr").read_text()
    poseidon2 = (root / "circuits_poseidon2" / "src" / "account_terminal.nr").read_text()

    keccak_core = keccak.split("pub fn assert_authenticated_leaf_value_commitment", 1)[0]
    poseidon2_core = poseidon2.split("pub fn assert_canonical_terminal_account_rlp", 1)[0]

    assert keccak_core == poseidon2_core


def test_keccak_expanded_account_verifier_remains_mechanically_synchronized() -> None:
    root = _thesis_c_root()
    standalone = (root / "circuits_mpt_inclusion" / "src" / "mpt_inclusion.nr").read_text()
    package_copy = (root / "circuits" / "src" / "expanded_account_verifier.nr").read_text()
    normalized = package_copy.replace(
        "crate::expanded_hash_keccak::hash_node",
        "crate::hash_keccak::hash_node",
    )

    assert normalized == standalone


def test_keccak_cutover_copied_support_modules_remain_exact_copies() -> None:
    root = _thesis_c_root()
    copies = {
        "expanded_hash_keccak.nr": (
            root / "circuits" / "src" / "expanded_hash_keccak.nr",
            root / "circuits_mpt_inclusion" / "src" / "hash_keccak.nr",
        ),
        "expanded_mpt_capacity.nr": (
            root / "circuits" / "src" / "expanded_mpt_capacity.nr",
            root / "circuits_mpt_inclusion" / "src" / "expanded_mpt_capacity.nr",
        ),
    }

    for name, (current, authoritative) in copies.items():
        assert current.read_bytes() == authoritative.read_bytes(), name
