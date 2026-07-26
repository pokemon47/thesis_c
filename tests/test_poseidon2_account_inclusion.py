from __future__ import annotations

import copy
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import tomllib

from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.statements.account_inclusion import AccountInclusionStatement


ROOT = Path(__file__).resolve().parents[1]
POSEIDON2_PACKAGE = ROOT / "circuits_poseidon2"
POSEIDON2_FIXTURE = (
    ROOT / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json"
)
POSEIDON2_CMD = (
    "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/"
    "build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}"
)


def _nargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(ROOT.parents[1])
    env["XDG_CACHE_HOME"] = str(ROOT.parents[1] / ".cache")
    env["NARGO_HOME"] = str(ROOT.parents[1] / "nargo")
    env["THESIS_C_POSEIDON2_CMD"] = POSEIDON2_CMD
    return env


def _valid_noir_inputs() -> dict[str, object]:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
        payload = load_proof_path(POSEIDON2_FIXTURE)[0]
        baseline = verify_account_payload(payload, Poseidon2Hash.from_environment())
        prepared = AccountInclusionStatement().prepare([payload], [baseline])
        noir_inputs = to_noir_input_map(prepared)
        assert noir_inputs["public_hash_variant_id"] == 2
        assert noir_inputs["witness_version"] == 1
        assert "public_leaf_value_commitment" not in noir_inputs
        return noir_inputs


def _execute_with_inputs(noir_inputs: dict[str, object], witness_name: str) -> subprocess.CompletedProcess[str]:
    package_prover_toml = POSEIDON2_PACKAGE / "Prover.toml"
    original = package_prover_toml.read_text(encoding="utf-8")
    try:
        write_prover_toml(package_prover_toml, noir_inputs)
        return subprocess.run(
            [
                "nargo",
                "execute",
                witness_name,
                "--program-dir",
                str(POSEIDON2_PACKAGE),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=_nargo_env(),
        )
    finally:
        package_prover_toml.write_text(original, encoding="utf-8")


def _flip_byte(value: list[int], index: int = 0) -> None:
    value[index] = (value[index] + 1) % 256


def test_poseidon2_account_inclusion_expanded_witness_executes_successfully() -> None:
    noir_inputs = _valid_noir_inputs()
    witness_name = "poseidon2_account_inclusion_expanded_smoke"
    witness_path = ROOT / "target" / f"{witness_name}.gz"
    witness_path.unlink(missing_ok=True)
    result = _execute_with_inputs(noir_inputs, witness_name)

    assert result.returncode == 0, result.stdout + result.stderr
    assert witness_path.exists()


@pytest.mark.parametrize(
    ("name", "mutator"),
    [
        ("wrong_root_bytes", lambda inputs: _flip_byte(inputs["public_state_root"], 0)),
        ("wrong_root_field", lambda inputs: inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 1)),
        (
            "root_bytes_field_mismatch",
            lambda inputs: (
                _flip_byte(inputs["public_state_root"], 0),
                inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 2),
            ),
        ),
        ("wrong_address", lambda inputs: _flip_byte(inputs["public_account_address"], 0)),
        ("wrong_trie_key", lambda inputs: _flip_byte(inputs["private_trie_key"], 0)),
        ("wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
        ("mutated_terminal", lambda inputs: _flip_byte(inputs["private_terminal_value"], 0)),
        ("unsupported_witness_version", lambda inputs: inputs.__setitem__("witness_version", int(inputs["witness_version"]) + 1)),
    ],
    ids=str,
)
def test_poseidon2_account_inclusion_rejects_mutations(name: str, mutator) -> None:
    noir_inputs = _valid_noir_inputs()
    mutated = copy.deepcopy(noir_inputs)
    mutator(mutated)
    result = _execute_with_inputs(mutated, f"poseidon2_account_inclusion_{name}")

    assert result.returncode != 0, result.stdout + result.stderr


def test_poseidon2_account_inclusion_public_abi_order_is_stable() -> None:
    noir_inputs = _valid_noir_inputs()
    assert list(noir_inputs)[:5] == [
        "witness_version",
        "public_state_root",
        "public_state_root_field",
        "public_account_address",
        "public_hash_variant_id",
    ]


def test_poseidon2_account_inclusion_generated_inputs_are_toml_round_trippable() -> None:
    noir_inputs = _valid_noir_inputs()
    with tempfile.TemporaryDirectory() as tmp_dir:
        toml_path = Path(tmp_dir) / "Prover.toml"
        write_prover_toml(toml_path, noir_inputs)
        generated = tomllib.loads(toml_path.read_text(encoding="utf-8"))

    assert generated["public_state_root_field"] == str(noir_inputs["public_state_root_field"])
    assert generated["private_active_node_count"] == noir_inputs["private_active_node_count"]
