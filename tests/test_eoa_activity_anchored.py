from __future__ import annotations

import copy
import io
import os
import subprocess
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import tomllib

from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.cli import build_parser
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.artifacts import resolve_circuit_package
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.statements.eoa_activity_anchored import (
    AnchoredEoaActivityStatement,
    AnchoredPoseidon2EoaActivityStatement,
)


ROOT = Path(__file__).resolve().parents[1]
THESIS_ROOT = ROOT.parents[1]
KECCAK_PACKAGE = ROOT / "circuits_eoa_activity_anchored"
POSEIDON2_PACKAGE = ROOT / "circuits_eoa_activity_anchored_poseidon2"
KECCAK_FIXTURE = ROOT / "datasets" / "eoa_activity" / "controlled_keccak_eoa_activity_mixed_depth3_4.json"
POSEIDON2_FIXTURE = ROOT / "datasets" / "eoa_activity" / "controlled_poseidon2_eoa_activity_mixed_depth2_4.json"
POSEIDON2_CMD = "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}"


def _nargo_env(hash_name: str) -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(THESIS_ROOT)
    env["XDG_CACHE_HOME"] = str(THESIS_ROOT / ".cache")
    env["NARGO_HOME"] = str(THESIS_ROOT / "nargo")
    if hash_name == "poseidon2":
        env["THESIS_C_POSEIDON2_CMD"] = POSEIDON2_CMD
    return env


def _payloads(hash_name: str):
    path = POSEIDON2_FIXTURE if hash_name == "poseidon2" else KECCAK_FIXTURE
    return load_proof_path(path)


def _baseline(hash_name: str, payload):
    if hash_name == "poseidon2":
        os.environ.setdefault("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
        return verify_account_payload(payload, Poseidon2Hash.from_environment())
    return verify_account_payload(payload, Keccak256Hash())


def _prepared(hash_name: str):
    payloads = _payloads(hash_name)
    baselines = [_baseline(hash_name, payload) for payload in payloads]
    statement = (
        AnchoredPoseidon2EoaActivityStatement()
        if hash_name == "poseidon2"
        else AnchoredEoaActivityStatement()
    )
    prepared = statement.prepare(payloads, baselines, allow_synthetic=True)
    return payloads, baselines, prepared, POSEIDON2_PACKAGE if hash_name == "poseidon2" else KECCAK_PACKAGE


def _run_execute(package_dir: Path, noir_inputs: dict[str, object], witness_name: str, hash_name: str) -> subprocess.CompletedProcess[str]:
    prover_toml = package_dir / "Prover.toml"
    original = prover_toml.read_text(encoding="utf-8") if prover_toml.exists() else None
    try:
        write_prover_toml(prover_toml, noir_inputs)
        return subprocess.run(
            ["nargo", "execute", witness_name, "--program-dir", str(package_dir)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=_nargo_env(hash_name),
        )
    finally:
        if original is None:
            prover_toml.unlink(missing_ok=True)
        else:
            prover_toml.write_text(original, encoding="utf-8")
        (ROOT / "target" / f"{witness_name}.gz").unlink(missing_ok=True)


def _swap_complete_tuples(inputs: dict[str, object]) -> None:
    swap_keys = [
        "public_block_hash_1",
        "public_state_root_1",
        "public_block_hash_2",
        "public_state_root_2",
        "public_state_root_1_field",
        "public_state_root_2_field",
        "header_witness_version_1",
        "private_header_bytes_1",
        "private_header_len_1",
        "account_witness_version_1",
        "private_trie_key_1",
        "private_active_node_count_1",
        "private_node_bytes_1",
        "private_node_lengths_1",
        "private_node_kinds_1",
        "private_node_list_layouts_1",
        "private_node_item_layouts_1",
        "private_node_compact_layouts_1",
        "private_selected_ref_layouts_1",
        "private_selected_ref_bytes_1",
        "private_selected_ref_lengths_1",
        "private_selected_ref_kinds_1",
        "private_terminal_value_1",
        "private_terminal_value_len_1",
        "private_leaf_path_nibbles_1",
        "private_leaf_path_len_1",
        "private_leaf_outer_list_layout_1",
        "private_leaf_compact_path_layout_1",
        "private_leaf_account_value_layout_1",
        "private_account_inner_list_layout_1",
        "private_account_nonce_layout_1",
        "private_account_balance_layout_1",
        "private_account_storage_root_layout_1",
        "private_account_code_hash_layout_1",
        "header_witness_version_2",
        "private_header_bytes_2",
        "private_header_len_2",
        "account_witness_version_2",
        "private_trie_key_2",
        "private_active_node_count_2",
        "private_node_bytes_2",
        "private_node_lengths_2",
        "private_node_kinds_2",
        "private_node_list_layouts_2",
        "private_node_item_layouts_2",
        "private_node_compact_layouts_2",
        "private_selected_ref_layouts_2",
        "private_selected_ref_bytes_2",
        "private_selected_ref_lengths_2",
        "private_selected_ref_kinds_2",
        "private_terminal_value_2",
        "private_terminal_value_len_2",
        "private_leaf_path_nibbles_2",
        "private_leaf_path_len_2",
        "private_leaf_outer_list_layout_2",
        "private_leaf_compact_path_layout_2",
        "private_leaf_account_value_layout_2",
        "private_account_inner_list_layout_2",
        "private_account_nonce_layout_2",
        "private_account_balance_layout_2",
        "private_account_storage_root_layout_2",
        "private_account_code_hash_layout_2",
    ]
    for key in swap_keys:
        if key not in inputs:
            continue
    for prefix in ("public_block_hash", "public_state_root"):
        inputs[f"{prefix}_1"], inputs[f"{prefix}_2"] = inputs[f"{prefix}_2"], inputs[f"{prefix}_1"]
    if "public_state_root_1_field" in inputs:
        inputs["public_state_root_1_field"], inputs["public_state_root_2_field"] = (
            inputs["public_state_root_2_field"],
            inputs["public_state_root_1_field"],
        )
    for prefix in (
        "header_witness_version",
        "private_header_bytes",
        "private_header_len",
        "account_witness_version",
        "private_trie_key",
        "private_active_node_count",
        "private_node_bytes",
        "private_node_lengths",
        "private_node_kinds",
        "private_node_list_layouts",
        "private_node_item_layouts",
        "private_node_compact_layouts",
        "private_selected_ref_layouts",
        "private_selected_ref_bytes",
        "private_selected_ref_lengths",
        "private_selected_ref_kinds",
        "private_terminal_value",
        "private_terminal_value_len",
        "private_leaf_path_nibbles",
        "private_leaf_path_len",
        "private_leaf_outer_list_layout",
        "private_leaf_compact_path_layout",
        "private_leaf_account_value_layout",
        "private_account_inner_list_layout",
        "private_account_nonce_layout",
        "private_account_balance_layout",
        "private_account_storage_root_layout",
        "private_account_code_hash_layout",
    ):
        inputs[f"{prefix}_1"], inputs[f"{prefix}_2"] = inputs[f"{prefix}_2"], inputs[f"{prefix}_1"]


def _mutations(hash_name: str):
    mutations = [
        ("wrong_block_hash_1", lambda i: i["public_block_hash_1"].__setitem__(0, i["public_block_hash_1"][0] ^ 1)),
        ("wrong_block_hash_2", lambda i: i["public_block_hash_2"].__setitem__(0, i["public_block_hash_2"][0] ^ 1)),
        ("wrong_state_root_1", lambda i: i["public_state_root_1"].__setitem__(0, i["public_state_root_1"][0] ^ 1)),
        ("wrong_state_root_2", lambda i: i["public_state_root_2"].__setitem__(0, i["public_state_root_2"][0] ^ 1)),
        ("wrong_public_address", lambda i: i["public_account_address"].__setitem__(0, i["public_account_address"][0] ^ 1)),
        ("wrong_hash_variant", lambda i: i.__setitem__("public_hash_variant_id", int(i["public_hash_variant_id"]) + 1)),
        ("swapped_headers_only", lambda i: _swap_headers_only(i)),
        ("swapped_account_proofs_only", lambda i: _swap_account_proofs_only(i)),
        ("mutated_code_hash_1", lambda i: i.__setitem__("private_account_code_hash_layout_1", copy.deepcopy(i["private_account_storage_root_layout_1"]))),
        ("mutated_code_hash_2", lambda i: i.__setitem__("private_account_code_hash_layout_2", copy.deepcopy(i["private_account_storage_root_layout_2"]))),
        ("equal_nonce", lambda i: _copy_state_one_to_state_two(i)),
        ("duplicate_same_state", lambda i: _copy_state_one_to_state_two(i)),
        ("wrong_header_version_1", lambda i: i.__setitem__("header_witness_version_1", int(i["header_witness_version_1"]) + 1)),
        ("wrong_header_version_2", lambda i: i.__setitem__("header_witness_version_2", int(i["header_witness_version_2"]) + 1)),
        ("nonzero_header_padding_1", lambda i: i["private_header_bytes_1"].__setitem__(int(i["private_header_len_1"]), 1)),
        ("nonzero_header_padding_2", lambda i: i["private_header_bytes_2"].__setitem__(int(i["private_header_len_2"]), 1)),
    ]
    if hash_name == "poseidon2":
        mutations.extend(
            [
                ("wrong_state_root_field_1", lambda i: i.__setitem__("public_state_root_1_field", int(i["public_state_root_1_field"]) + 1)),
                ("wrong_state_root_field_2", lambda i: i.__setitem__("public_state_root_2_field", int(i["public_state_root_2_field"]) + 1)),
            ]
        )
    return mutations


def _swap_headers_only(inputs: dict[str, object]) -> None:
    inputs["public_block_hash_1"], inputs["public_block_hash_2"] = (
        inputs["public_block_hash_2"],
        inputs["public_block_hash_1"],
    )
    inputs["public_state_root_1"], inputs["public_state_root_2"] = (
        inputs["public_state_root_2"],
        inputs["public_state_root_1"],
    )
    if "public_state_root_1_field" in inputs:
        inputs["public_state_root_1_field"], inputs["public_state_root_2_field"] = (
            inputs["public_state_root_2_field"],
            inputs["public_state_root_1_field"],
        )
    inputs["header_witness_version_1"], inputs["header_witness_version_2"] = (
        inputs["header_witness_version_2"],
        inputs["header_witness_version_1"],
    )
    inputs["private_header_bytes_1"], inputs["private_header_bytes_2"] = (
        inputs["private_header_bytes_2"],
        inputs["private_header_bytes_1"],
    )
    inputs["private_header_len_1"], inputs["private_header_len_2"] = (
        inputs["private_header_len_2"],
        inputs["private_header_len_1"],
    )


def _swap_account_proofs_only(inputs: dict[str, object]) -> None:
    for key in [
        "private_trie_key",
        "private_active_node_count",
        "private_node_bytes",
        "private_node_lengths",
        "private_node_kinds",
        "private_node_list_layouts",
        "private_node_item_layouts",
        "private_node_compact_layouts",
        "private_selected_ref_layouts",
        "private_selected_ref_bytes",
        "private_selected_ref_lengths",
        "private_selected_ref_kinds",
        "private_terminal_value",
        "private_terminal_value_len",
        "private_leaf_path_nibbles",
        "private_leaf_path_len",
        "private_leaf_outer_list_layout",
        "private_leaf_compact_path_layout",
        "private_leaf_account_value_layout",
        "private_account_inner_list_layout",
        "private_account_nonce_layout",
        "private_account_balance_layout",
        "private_account_storage_root_layout",
        "private_account_code_hash_layout",
    ]:
        inputs[f"{key}_1"], inputs[f"{key}_2"] = inputs[f"{key}_2"], inputs[f"{key}_1"]


def _copy_state_one_to_state_two(inputs: dict[str, object]) -> None:
    for key in list(inputs):
        if key.endswith("_1"):
            inputs[key[:-2] + "_2"] = copy.deepcopy(inputs[key])
    inputs["public_block_hash_2"] = copy.deepcopy(inputs["public_block_hash_1"])
    inputs["public_state_root_2"] = copy.deepcopy(inputs["public_state_root_1"])
    if "public_state_root_1_field" in inputs:
        inputs["public_state_root_2_field"] = copy.deepcopy(inputs["public_state_root_1_field"])


@pytest.mark.parametrize("hash_name", ["keccak256", "poseidon2"])
def test_anchored_eoa_prepare_and_generate_witness(hash_name: str) -> None:
    payloads, _, prepared, _ = _prepared(hash_name)
    noir_inputs = to_noir_input_map(prepared)

    expected_prefix = [
        "witness_version",
        "public_block_hash_1",
        "public_state_root_1",
    ]
    if hash_name == "poseidon2":
        expected_prefix.append("public_state_root_1_field")
    expected_prefix += [
        "public_block_hash_2",
        "public_state_root_2",
    ]
    if hash_name == "poseidon2":
        expected_prefix.append("public_state_root_2_field")
    expected_prefix += [
        "public_account_address",
        "public_hash_variant_id",
        "header_witness_version_1",
        "private_header_bytes_1",
        "private_header_len_1",
        "account_witness_version_1",
    ]

    assert list(noir_inputs)[: len(expected_prefix)] == expected_prefix
    assert noir_inputs["public_hash_variant_id"] == int(prepared.public_inputs["hash_variant_id"])
    assert noir_inputs["public_account_address"] == list(
        bytes.fromhex(str(payloads[0].address)[2:])
    )
    if hash_name == "poseidon2":
        assert noir_inputs["public_state_root_1_field"] == int(prepared.public_inputs["state_root_1"], 16)
        assert noir_inputs["public_state_root_2_field"] == int(prepared.public_inputs["state_root_2"], 16)


@pytest.mark.parametrize("hash_name", ["keccak256", "poseidon2"])
def test_anchored_eoa_rejects_missing_real_header_data_by_default(hash_name: str) -> None:
    payloads = _payloads(hash_name)
    baselines = [_baseline(hash_name, payload) for payload in payloads]
    statement = (
        AnchoredPoseidon2EoaActivityStatement()
        if hash_name == "poseidon2"
        else AnchoredEoaActivityStatement()
    )

    with pytest.raises(LookupError, match="Synthetic headers are test-only"):
        statement.prepare(payloads, baselines)


@pytest.mark.parametrize("hash_name", ["keccak256", "poseidon2"])
def test_anchored_eoa_explicit_synthetic_fixture_preparation_is_marked_synthetic(hash_name: str) -> None:
    payloads, _, prepared, _ = _prepared(hash_name)

    assert prepared.metadata["header_fixture_classification_1"] == "synthetic"
    assert prepared.metadata["header_fixture_classification_2"] == "synthetic"
    assert prepared.metadata["header_rlp_source_1"] == "synthetic"
    assert prepared.metadata["header_rlp_source_2"] == "synthetic"
    assert prepared.metadata["header_source_reference_1"] == payloads[0].source_file
    assert prepared.metadata["header_source_reference_2"] == payloads[1].source_file


@pytest.mark.parametrize("hash_name", ["keccak256", "poseidon2"])
def test_anchored_eoa_positive_and_tuple_swap_execute(hash_name: str) -> None:
    payloads, baselines, prepared, package = _prepared(hash_name)
    noir_inputs = to_noir_input_map(prepared)

    positive = _run_execute(package, noir_inputs, f"anchored_eoa_positive_{hash_name}", hash_name)
    assert positive.returncode == 0, positive.stdout + positive.stderr

    swapped_payloads = [payloads[1], payloads[0]]
    swapped_baselines = [baselines[1], baselines[0]]
    swapped_statement = (
        AnchoredPoseidon2EoaActivityStatement()
        if hash_name == "poseidon2"
        else AnchoredEoaActivityStatement()
    )
    swapped_prepared = swapped_statement.prepare(swapped_payloads, swapped_baselines, allow_synthetic=True)
    swapped_inputs = to_noir_input_map(swapped_prepared)
    swapped = _run_execute(package, swapped_inputs, f"anchored_eoa_swapped_{hash_name}", hash_name)
    assert swapped.returncode == 0, swapped.stdout + swapped.stderr


@pytest.mark.parametrize("hash_name", ["keccak256", "poseidon2"])
@pytest.mark.parametrize("mutation_name,mutator", [
    ("wrong_block_hash_1", lambda i: i["public_block_hash_1"].__setitem__(0, i["public_block_hash_1"][0] ^ 1)),
    ("wrong_block_hash_2", lambda i: i["public_block_hash_2"].__setitem__(0, i["public_block_hash_2"][0] ^ 1)),
    ("wrong_state_root_1", lambda i: i["public_state_root_1"].__setitem__(0, i["public_state_root_1"][0] ^ 1)),
    ("wrong_state_root_2", lambda i: i["public_state_root_2"].__setitem__(0, i["public_state_root_2"][0] ^ 1)),
    ("wrong_public_address", lambda i: i["public_account_address"].__setitem__(0, i["public_account_address"][0] ^ 1)),
    ("wrong_hash_variant", lambda i: i.__setitem__("public_hash_variant_id", int(i["public_hash_variant_id"]) + 1)),
    ("swapped_headers_only", _swap_headers_only),
    ("swapped_account_proofs_only", _swap_account_proofs_only),
    ("equal_nonce", _copy_state_one_to_state_two),
    ("wrong_header_version_1", lambda i: i.__setitem__("header_witness_version_1", int(i["header_witness_version_1"]) + 1)),
    ("nonzero_header_padding_1", lambda i: i["private_header_bytes_1"].__setitem__(int(i["private_header_len_1"]), 1)),
])
def test_anchored_eoa_negative_execute(
    hash_name: str,
    mutation_name: str,
    mutator,
) -> None:
    _, _, prepared, package = _prepared(hash_name)
    noir_inputs = to_noir_input_map(prepared)
    mutator(noir_inputs)
    result = _run_execute(package, noir_inputs, f"anchored_eoa_{mutation_name}_{hash_name}", hash_name)
    assert result.returncode != 0, result.stdout + result.stderr


def test_anchored_eoa_source_sync_and_routing() -> None:
    anchored_keccak = ROOT / "circuits_eoa_activity_anchored" / "src"
    anchored_poseidon2 = ROOT / "circuits_eoa_activity_anchored_poseidon2" / "src"
    assert (anchored_keccak / "rlp_balance.nr").read_bytes() == (
        ROOT / "circuits_eoa_activity" / "src" / "rlp_balance.nr"
    ).read_bytes()
    assert (anchored_poseidon2 / "rlp_balance.nr").read_bytes() == (
        ROOT / "circuits_eoa_activity_poseidon2" / "src" / "rlp_balance.nr"
    ).read_bytes()
    assert resolve_circuit_package("eoa_activity_anchored", "keccak256", ROOT).package_dir == KECCAK_PACKAGE
    assert (
        resolve_circuit_package("eoa_activity_anchored_poseidon2", "poseidon2", ROOT).package_dir
        == POSEIDON2_PACKAGE
    )


@pytest.mark.parametrize("hash_name", ["keccak256", "poseidon2"])
def test_anchored_eoa_duplicate_state_prepare_rejects_equal_nonce(hash_name: str) -> None:
    payloads = _payloads(hash_name)
    baselines = [_baseline(hash_name, payload) for payload in payloads]
    payloads = [copy.deepcopy(payloads[0]), copy.deepcopy(payloads[0])]
    baselines = [copy.deepcopy(baselines[0]), copy.deepcopy(baselines[0])]
    statement = (
        AnchoredPoseidon2EoaActivityStatement()
        if hash_name == "poseidon2"
        else AnchoredEoaActivityStatement()
    )

    with pytest.raises(ValueError, match="nonce inequality"):
        statement.prepare(payloads, baselines, allow_synthetic=True)
