from __future__ import annotations

import copy
import os
import subprocess
from contextlib import contextmanager
from pathlib import Path

import pytest

from thesis_c.baseline.account_layout import parse_nested_account_layout, payload_slice
from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.proof_inputs.normalizer import hex_to_bytes
from thesis_c.statements.codehash_verification import (
    CodeHashVerificationStatement,
    parse_code_hash_bytes,
)
from thesis_c.statements.codehash_verification_anchored import (
    AnchoredCodeHashVerificationStatement,
)
from thesis_c.statements.codehash_verification_anchored_poseidon2 import (
    AnchoredPoseidon2CodeHashVerificationStatement,
)


KECCAK_FOREST = Path("/Users/doodleaks/Developer/Thesis/sample_proofs/proof_keccak_forest.json")
THESIS_C_ROOT = Path(__file__).resolve().parents[1]
KECCAK_PACKAGE = THESIS_C_ROOT / "circuits_codehash_anchored"
POSEIDON2_PACKAGE = THESIS_C_ROOT / "circuits_codehash_anchored_poseidon2"
POSEIDON2_CMD = (
    "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/"
    "build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}"
)


def _nargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(THESIS_C_ROOT.parents[1])
    env["XDG_CACHE_HOME"] = str(THESIS_C_ROOT.parents[1] / ".cache")
    env["NARGO_HOME"] = str(THESIS_C_ROOT.parents[1] / "nargo")
    return env


def _prepared(statement: CodeHashVerificationStatement | None = None):
    payload = load_proof_path(KECCAK_FOREST)[0]
    baseline = verify_account_payload(payload, Keccak256Hash())
    return (statement or CodeHashVerificationStatement()).prepare([payload], [baseline])


def _poseidon2_prepared(statement: CodeHashVerificationStatement | None = None):
    poseidon2_path = THESIS_C_ROOT / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json"
    payload = load_proof_path(poseidon2_path)[0]
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
        baseline = verify_account_payload(payload, Poseidon2Hash.from_environment())
    return (statement or CodeHashVerificationStatement()).prepare([payload], [baseline])


def _execute_with_inputs(
    package_dir: Path,
    noir_inputs: dict[str, object],
    witness_name: str,
) -> subprocess.CompletedProcess[str]:
    package_prover_toml = package_dir / "Prover.toml"
    original = package_prover_toml.read_text(encoding="utf-8") if package_prover_toml.exists() else None
    try:
        write_prover_toml(package_prover_toml, noir_inputs)
        return subprocess.run(
            [
                "nargo",
                "execute",
                witness_name,
                "--program-dir",
                str(package_dir),
            ],
            cwd=THESIS_C_ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=_nargo_env(),
        )
    finally:
        if original is None:
            package_prover_toml.unlink(missing_ok=True)
        else:
            package_prover_toml.write_text(original, encoding="utf-8")


def _mutate_bytes32(value: list[int], index: int, delta: int = 1) -> list[int]:
    mutated = list(value)
    mutated[index] = (mutated[index] + delta) % 256
    return mutated


def _mutate_codehash_inputs(noir_inputs: dict[str, object], *, hash_name: str) -> dict[str, object]:
    mutated = copy.deepcopy(noir_inputs)
    mutated["public_expected_code_hash"] = _mutate_bytes32(
        list(mutated["public_expected_code_hash"]),
        0,
    )
    return mutated


def _valid_codehash_noir_inputs(hash_name: str) -> tuple[dict[str, object], Path]:
    if hash_name == "poseidon2":
        payload_path = (
            THESIS_C_ROOT / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json"
        )
        payload = load_proof_path(payload_path)[0]
        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setenv("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
            baseline = verify_account_payload(payload, Poseidon2Hash.from_environment())
        prepared = AnchoredPoseidon2CodeHashVerificationStatement().prepare([payload], [baseline])
        return to_noir_input_map(prepared), POSEIDON2_PACKAGE

    payload_path = THESIS_C_ROOT / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json"
    payload = load_proof_path(payload_path)[0]
    baseline = verify_account_payload(payload, Keccak256Hash())
    prepared = AnchoredCodeHashVerificationStatement().prepare([payload], [baseline])
    return to_noir_input_map(prepared), KECCAK_PACKAGE


@contextmanager
def _temporary_noir_inputs(package_dir: Path, noir_inputs: dict[str, object]):
    package_prover_toml = package_dir / "Prover.toml"
    original = package_prover_toml.read_text(encoding="utf-8") if package_prover_toml.exists() else None
    try:
        write_prover_toml(package_prover_toml, noir_inputs)
        yield
    finally:
        if original is None:
            package_prover_toml.unlink(missing_ok=True)
        else:
            package_prover_toml.write_text(original, encoding="utf-8")


def test_strict_code_hash_parser_accepts_exact_32_bytes() -> None:
    assert parse_code_hash_bytes("0x" + "11" * 32) == bytes.fromhex("11" * 32)
    assert parse_code_hash_bytes("22" * 32) == bytes.fromhex("22" * 32)


@pytest.mark.parametrize("value", ["0x", "0x11", "0x" + "11" * 31, "0x" + "11" * 33, "zz" * 32])
def test_strict_code_hash_parser_rejects_non_bytes32(value: str) -> None:
    with pytest.raises(ValueError):
        parse_code_hash_bytes(value)


def test_prepares_valid_empty_code_hash_from_verified_leaf() -> None:
    prepared = _prepared()

    assert prepared.statement_name == "codehash_verification"
    assert prepared.public_inputs["expected_code_hash"] == (
        "0x" + Keccak256Hash().digest(b"").hex()
    )
    assert prepared.metadata["code_hash_class"] == "eoa_empty_code_hash"
    assert "decoded_code_hash" not in prepared.private_inputs
    assert "public_leaf_value_commitment" not in prepared.public_inputs


def test_explicit_expected_code_hash_takes_precedence() -> None:
    payload = load_proof_path(KECCAK_FOREST)[0]
    explicit = payload.code_hash.upper().replace("0X", "0x")

    prepared = _prepared(CodeHashVerificationStatement(expected_code_hash=explicit))

    assert prepared.public_inputs["expected_code_hash"] == payload.code_hash.lower()
    assert prepared.metadata["expected_code_hash_source"] == "explicit"


def test_wrong_explicit_expected_code_hash_fails_production_prepare() -> None:
    with pytest.raises(ValueError, match="Expected codeHash does not match"):
        _prepared(CodeHashVerificationStatement(expected_code_hash="0x" + "12" * 32))


def test_wrong_claim_test_path_reaches_noir_mapping() -> None:
    prepared = _prepared(
        CodeHashVerificationStatement(
            expected_code_hash="0x" + "12" * 32,
            allow_wrong_claim_for_testing=True,
        )
    )

    noir_inputs = to_noir_input_map(prepared)

    assert noir_inputs["public_expected_code_hash"] == [0x12] * 32
    assert "private_decoded_code_hash" not in noir_inputs
    assert "public_leaf_value_commitment" not in noir_inputs


@pytest.mark.parametrize("hash_name", ["keccak256", "poseidon2"])
def test_codehash_positive_execute_succeeds(hash_name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    if hash_name == "poseidon2":
        monkeypatch.setenv("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
    noir_inputs, package_dir = _valid_codehash_noir_inputs(hash_name)
    result = _execute_with_inputs(package_dir, noir_inputs, f"{hash_name}_codehash_positive")
    assert result.returncode == 0, result.stdout + result.stderr


def test_code_hash_layout_payload_matches_decoded_code_hash() -> None:
    payload = load_proof_path(KECCAK_FOREST)[0]
    baseline = verify_account_payload(payload, Keccak256Hash())
    leaf = hex_to_bytes(payload.account_proof[-1])
    _, account_layout = parse_nested_account_layout(leaf)

    assert payload_slice(leaf, account_layout.code_hash).hex() == baseline.leaf.code_hash[2:]
    assert account_layout.code_hash.payload_len == 32


@pytest.mark.parametrize(
    ("mutator_name", "mutator"),
    [
        ("wrong_root", lambda inputs: inputs.__setitem__("public_state_root", _mutate_bytes32(list(inputs["public_state_root"]), 0))),
        ("wrong_address", lambda inputs: inputs.__setitem__("public_account_address", _mutate_bytes32(list(inputs["public_account_address"]), 0))),
        ("wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
        ("codehash_byte_0", lambda inputs: inputs.__setitem__("public_expected_code_hash", _mutate_bytes32(list(inputs["public_expected_code_hash"]), 0))),
        ("codehash_byte_mid", lambda inputs: inputs.__setitem__("public_expected_code_hash", _mutate_bytes32(list(inputs["public_expected_code_hash"]), 16))),
        ("codehash_byte_31", lambda inputs: inputs.__setitem__("public_expected_code_hash", _mutate_bytes32(list(inputs["public_expected_code_hash"]), 31))),
        ("codehash_layout_offset", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(0, int(inputs["private_account_code_hash_layout"][0]) + 1)),
        ("codehash_layout_to_storage_root", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(0, int(inputs["private_account_storage_root_layout"][0]))),
        ("codehash_payload_31", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(3, 31)),
        ("codehash_payload_33", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(3, 33)),
        ("malformed_prefix", lambda inputs: inputs["private_node_bytes"][3].__setitem__(int(inputs["private_account_code_hash_layout"][0]), 0xA1)),
        ("trailing_account_bytes", lambda inputs: inputs["private_account_inner_list_layout"].__setitem__(1, int(inputs["private_account_inner_list_layout"][1]) + 1)),
    ],
)
def test_keccak_codehash_negative_executions_fail(mutator_name: str, mutator) -> None:
    noir_inputs, package_dir = _valid_codehash_noir_inputs("keccak256")
    mutated = copy.deepcopy(noir_inputs)
    mutator(mutated)
    result = _execute_with_inputs(package_dir, mutated, f"keccak_codehash_{mutator_name}")

    assert result.returncode != 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("mutator_name", "mutator"),
    [
        ("wrong_root", lambda inputs: inputs.__setitem__("public_state_root", _mutate_bytes32(list(inputs["public_state_root"]), 0))),
        ("wrong_root_field", lambda inputs: inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 1)),
        ("root_bytes_field_mismatch", lambda inputs: (
            inputs.__setitem__("public_state_root", _mutate_bytes32(list(inputs["public_state_root"]), 0)),
            inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 2),
        )),
        ("wrong_address", lambda inputs: inputs.__setitem__("public_account_address", _mutate_bytes32(list(inputs["public_account_address"]), 0))),
        ("wrong_private_address_hash", lambda inputs: inputs.__setitem__("private_address_hash", _mutate_bytes32(list(inputs["private_address_hash"]), 0))),
        ("wrong_private_trie_key", lambda inputs: inputs.__setitem__("private_trie_key", _mutate_bytes32(list(inputs["private_trie_key"]), 0))),
        ("wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
        ("codehash_byte_0", lambda inputs: inputs.__setitem__("public_expected_code_hash", _mutate_bytes32(list(inputs["public_expected_code_hash"]), 0))),
        ("codehash_byte_mid", lambda inputs: inputs.__setitem__("public_expected_code_hash", _mutate_bytes32(list(inputs["public_expected_code_hash"]), 16))),
        ("codehash_byte_31", lambda inputs: inputs.__setitem__("public_expected_code_hash", _mutate_bytes32(list(inputs["public_expected_code_hash"]), 31))),
        ("codehash_layout_offset", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(0, int(inputs["private_account_code_hash_layout"][0]) + 1)),
        ("codehash_layout_to_storage_root", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(0, int(inputs["private_account_storage_root_layout"][0]))),
        ("codehash_payload_31", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(3, 31)),
        ("codehash_payload_33", lambda inputs: inputs["private_account_code_hash_layout"].__setitem__(3, 33)),
        ("malformed_prefix", lambda inputs: inputs["private_node_bytes"][3].__setitem__(int(inputs["private_account_code_hash_layout"][0]), 0xA1)),
        ("trailing_account_bytes", lambda inputs: inputs["private_account_inner_list_layout"].__setitem__(1, int(inputs["private_account_inner_list_layout"][1]) + 1)),
    ],
)
def test_poseidon2_codehash_negative_executions_fail(mutator_name: str, mutator, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
    noir_inputs, package_dir = _valid_codehash_noir_inputs("poseidon2")
    mutated = copy.deepcopy(noir_inputs)
    mutator(mutated)
    result = _execute_with_inputs(package_dir, mutated, f"poseidon2_codehash_{mutator_name}")

    assert result.returncode != 0, result.stdout + result.stderr
