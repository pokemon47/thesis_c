from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import Callable

import pytest

from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.witness_writer import render_prover_toml
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.statements.eoa_activity import EoaActivityStatement


ROOT = Path(__file__).parents[1]
KECCAK_PACKAGE = ROOT / "circuits_eoa_activity"
POSEIDON2_PACKAGE = ROOT / "circuits_eoa_activity_poseidon2"
KECCAK_FIXTURE = ROOT / "tests/fixtures/datasets/eoa_activity/synthetic_keccak_eoa_activity_pair.json"
POSEIDON2_FIXTURE = ROOT / "tests/fixtures/datasets/eoa_activity/synthetic_poseidon2_eoa_activity_pair.json"
NONEMPTY_KECCAK_FIXTURE = ROOT / "tests/fixtures/datasets/eoa_activity/synthetic_keccak_nonempty_codehash_pair.json"


@dataclass(frozen=True)
class Mutation:
    name: str
    hash_name: str
    mutate: Callable[[dict[str, object]], None]
    source_fixture: Path | None = None
    statement_kwargs: dict[str, object] | None = None
    duplicate_second_payload: bool = False


def _hash(name: str):
    if name == "keccak256":
        return Keccak256Hash()
    return Poseidon2Hash.from_environment()


def _valid_inputs(
    hash_name: str,
    *,
    fixture: Path | None = None,
    statement_kwargs: dict[str, object] | None = None,
    duplicate_second_payload: bool = False,
) -> dict[str, object]:
    payloads = load_proof_path(fixture or (POSEIDON2_FIXTURE if hash_name == "poseidon2" else KECCAK_FIXTURE))
    if duplicate_second_payload:
        payloads = [payloads[1], load_proof_path(KECCAK_FIXTURE)[0]]
    baselines = [verify_account_payload(payload, _hash(hash_name)) for payload in payloads]
    prepared = EoaActivityStatement(**(statement_kwargs or {})).prepare(payloads, baselines)
    return to_noir_input_map(prepared)


def _flip_byte(values: list[int], index: int = 0) -> None:
    values[index] ^= 1


def _flip_scalar_field(inputs: dict[str, object], key: str) -> None:
    inputs[key] = int(inputs[key]) + 1


def _flip_field_list(values: list[int], index: int = 0) -> None:
    values[index] = int(values[index]) + 1


def _flip_nested_field(values: list[list[int]], outer: int = 0, index: int = 0) -> None:
    values[outer][index] = int(values[outer][index]) + 1


def _copy_state_one_to_state_two(inputs: dict[str, object]) -> None:
    for key in list(inputs):
        if key.endswith("_1"):
            inputs[key[:-2] + "_2"] = deepcopy(inputs[key])
    inputs["public_state_root_2"] = deepcopy(inputs["public_state_root_1"])
    if "public_state_root_1_field" in inputs:
        inputs["public_state_root_2_field"] = inputs["public_state_root_1_field"]


def _mutate_layout_to_storage_root(inputs: dict[str, object], state: int) -> None:
    inputs[f"private_account_code_hash_layout_{state}"] = deepcopy(
        inputs[f"private_account_storage_root_layout_{state}"]
    )


def _mutate_nonce_layout(inputs: dict[str, object], state: int) -> None:
    inputs[f"private_account_nonce_layout_{state}"] = [38, 0, 38, 0]


def _mutate_public_root(inputs: dict[str, object], state: int) -> None:
    _flip_byte(inputs[f"public_state_root_{state}"])


def _mutate_node(inputs: dict[str, object], state: int) -> None:
    inputs[f"private_node_bytes_{state}"][0][0] ^= 1


def _mutate_selected_ref_bytes(inputs: dict[str, object], state: int) -> None:
    inputs[f"private_selected_ref_bytes_{state}"][0][0] ^= 1


def _mutate_selected_ref_length(inputs: dict[str, object], state: int) -> None:
    values = inputs[f"private_selected_ref_lengths_{state}"]
    values[0] = int(values[0]) + 1


def _mutate_wrong_address(inputs: dict[str, object]) -> None:
    _flip_byte(inputs["public_account_address"], 0)


def _mutate_hash_variant(inputs: dict[str, object]) -> None:
    inputs["public_hash_variant_id"] = 99


def _mutate_swap_roots(inputs: dict[str, object]) -> None:
    inputs["public_state_root_1"], inputs["public_state_root_2"] = (
        inputs["public_state_root_2"],
        inputs["public_state_root_1"],
    )
    if "public_state_root_1_field" in inputs:
        inputs["public_state_root_1_field"], inputs["public_state_root_2_field"] = (
            inputs["public_state_root_2_field"],
            inputs["public_state_root_1_field"],
        )


def _mutations(hash_name: str) -> list[Mutation]:
    common = [
        Mutation(f"{hash_name}_wrong_public_address", hash_name, _mutate_wrong_address),
        Mutation(f"{hash_name}_wrong_hash_variant", hash_name, _mutate_hash_variant),
        Mutation(f"{hash_name}_wrong_root_1", hash_name, lambda i: _mutate_public_root(i, 1)),
        Mutation(f"{hash_name}_wrong_root_2", hash_name, lambda i: _mutate_public_root(i, 2)),
        Mutation(f"{hash_name}_tampered_proof_node_1", hash_name, lambda i: _mutate_node(i, 1)),
        Mutation(f"{hash_name}_tampered_proof_node_2", hash_name, lambda i: _mutate_node(i, 2)),
        Mutation(
            f"{hash_name}_wrong_selected_ref_bytes_1",
            hash_name,
            lambda i: _mutate_selected_ref_bytes(i, 1),
        ),
        Mutation(
            f"{hash_name}_wrong_selected_ref_bytes_2",
            hash_name,
            lambda i: _mutate_selected_ref_bytes(i, 2),
        ),
        Mutation(
            f"{hash_name}_wrong_selected_ref_length_1",
            hash_name,
            lambda i: _mutate_selected_ref_length(i, 1),
        ),
        Mutation(
            f"{hash_name}_wrong_selected_ref_length_2",
            hash_name,
            lambda i: _mutate_selected_ref_length(i, 2),
        ),
        Mutation(f"{hash_name}_malformed_nonce_layout_1", hash_name, lambda i: _mutate_nonce_layout(i, 1)),
        Mutation(f"{hash_name}_malformed_nonce_layout_2", hash_name, lambda i: _mutate_nonce_layout(i, 2)),
        Mutation(f"{hash_name}_swapped_proof_root_pairing", hash_name, _mutate_swap_roots),
        Mutation(
            f"{hash_name}_equal_nonce",
            hash_name,
            _copy_state_one_to_state_two,
        ),
        Mutation(
            f"{hash_name}_nonempty_code_hash_1",
            hash_name,
            (lambda i: None)
            if hash_name == "keccak256"
            else (lambda i: _mutate_layout_to_storage_root(i, 1)),
            source_fixture=NONEMPTY_KECCAK_FIXTURE if hash_name == "keccak256" else None,
            statement_kwargs={"allow_non_empty_code_hash_for_testing": True}
            if hash_name == "keccak256"
            else None,
            duplicate_second_payload=hash_name == "keccak256",
        ),
        Mutation(
            f"{hash_name}_nonempty_code_hash_2",
            hash_name,
            (lambda i: None)
            if hash_name == "keccak256"
            else (lambda i: _mutate_layout_to_storage_root(i, 2)),
            source_fixture=NONEMPTY_KECCAK_FIXTURE if hash_name == "keccak256" else None,
            statement_kwargs={"allow_non_empty_code_hash_for_testing": True}
            if hash_name == "keccak256"
            else None,
        ),
    ]
    if hash_name != "poseidon2":
        return common

    return common + [
        Mutation("poseidon2_wrong_root_field_1", hash_name, lambda i: _flip_scalar_field(i, "public_state_root_1_field")),
        Mutation("poseidon2_wrong_root_field_2", hash_name, lambda i: _flip_scalar_field(i, "public_state_root_2_field")),
        Mutation("poseidon2_root_bytes_field_mismatch_1", hash_name, lambda i: _flip_scalar_field(i, "public_state_root_1_field")),
        Mutation("poseidon2_root_bytes_field_mismatch_2", hash_name, lambda i: _flip_scalar_field(i, "public_state_root_2_field")),
        Mutation("poseidon2_wrong_address_hash_1", hash_name, lambda i: _flip_byte(i["private_address_hash_1"])),
        Mutation("poseidon2_wrong_address_hash_2", hash_name, lambda i: _flip_byte(i["private_address_hash_2"])),
        Mutation("poseidon2_wrong_branch_child_field_1", hash_name, lambda i: _flip_field_list(i["private_branch_child_hash_fields_1"])),
        Mutation("poseidon2_wrong_branch_child_field_2", hash_name, lambda i: _flip_field_list(i["private_branch_child_hash_fields_2"])),
    ]


def _run_mutation(mutation: Mutation, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    package = POSEIDON2_PACKAGE if mutation.hash_name == "poseidon2" else KECCAK_PACKAGE
    package_prover = package / "Prover.toml"
    original = package_prover.read_bytes()
    inputs = _valid_inputs(
        mutation.hash_name,
        fixture=mutation.source_fixture,
        statement_kwargs=mutation.statement_kwargs,
        duplicate_second_payload=mutation.duplicate_second_payload,
    )
    mutation.mutate(inputs)
    package_prover.write_text(render_prover_toml(inputs), encoding="utf-8")
    witness_name = f"negative_{mutation.name}"
    try:
        result = subprocess.run(
            ["nargo", "execute", witness_name, "--program-dir", str(package)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        (tmp_path / f"{mutation.name}.stdout").write_text(result.stdout, encoding="utf-8")
        (tmp_path / f"{mutation.name}.stderr").write_text(result.stderr, encoding="utf-8")
        return result
    finally:
        package_prover.write_bytes(original)
        assert package_prover.read_bytes() == original


@pytest.mark.parametrize(
    "mutation",
    _mutations("keccak256"),
    ids=lambda mutation: mutation.name,
)
def test_keccak_eoa_activity_full_entrypoint_negative(mutation: Mutation, tmp_path: Path) -> None:
    result = _run_mutation(mutation, tmp_path)
    assert result.returncode != 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "mutation",
    _mutations("poseidon2"),
    ids=lambda mutation: mutation.name,
)
def test_poseidon2_eoa_activity_full_entrypoint_negative(
    mutation: Mutation,
    tmp_path: Path,
) -> None:
    result = _run_mutation(mutation, tmp_path)
    assert result.returncode != 0, result.stdout + result.stderr
