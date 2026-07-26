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
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.statements.balance_verification_anchored import AnchoredBalanceVerificationStatement
from thesis_c.statements.balance_verification_anchored_poseidon2 import (
    AnchoredPoseidon2BalanceVerificationStatement,
)
from thesis_c.statements.codehash_verification_anchored import AnchoredCodeHashVerificationStatement
from thesis_c.statements.codehash_verification_anchored_poseidon2 import (
    AnchoredPoseidon2CodeHashVerificationStatement,
)


ROOT = Path(__file__).resolve().parents[1]
THESIS_ROOT = ROOT.parents[1]
KECCAK_FIXTURE = ROOT / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json"
POSEIDON2_FIXTURE = ROOT / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json"
BALANCE_KECCAK_PACKAGE = ROOT / "circuits_balance_anchored"
BALANCE_POSEIDON2_PACKAGE = ROOT / "circuits_balance_anchored_poseidon2"
CODEHASH_KECCAK_PACKAGE = ROOT / "circuits_codehash_anchored"
CODEHASH_POSEIDON2_PACKAGE = ROOT / "circuits_codehash_anchored_poseidon2"
POSEIDON2_CMD = "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}"


def _nargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(THESIS_ROOT)
    env["XDG_CACHE_HOME"] = str(THESIS_ROOT / ".cache")
    env["NARGO_HOME"] = str(THESIS_ROOT / "nargo")
    env["THESIS_C_POSEIDON2_CMD"] = POSEIDON2_CMD
    return env


def _payload(hash_name: str):
    path = KECCAK_FIXTURE if hash_name == "keccak256" else POSEIDON2_FIXTURE
    return load_proof_path(path)[0]


def _baseline(hash_name: str, payload):
    if hash_name == "keccak256":
        return verify_account_payload(payload, Keccak256Hash())
    os.environ.setdefault("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
    return verify_account_payload(payload, Poseidon2Hash.from_environment())


def _prepare_balance(hash_name: str):
    payload = _payload(hash_name)
    baseline = _baseline(hash_name, payload)
    if hash_name == "keccak256":
        prepared = AnchoredBalanceVerificationStatement().prepare([payload], [baseline])
        return payload, baseline, prepared, BALANCE_KECCAK_PACKAGE
    prepared = AnchoredPoseidon2BalanceVerificationStatement().prepare([payload], [baseline])
    return payload, baseline, prepared, BALANCE_POSEIDON2_PACKAGE


def _prepare_codehash(hash_name: str):
    payload = _payload(hash_name)
    baseline = _baseline(hash_name, payload)
    if hash_name == "keccak256":
        prepared = AnchoredCodeHashVerificationStatement().prepare([payload], [baseline])
        return payload, baseline, prepared, CODEHASH_KECCAK_PACKAGE
    prepared = AnchoredPoseidon2CodeHashVerificationStatement().prepare([payload], [baseline])
    return payload, baseline, prepared, CODEHASH_POSEIDON2_PACKAGE


def _run_execute(package_dir: Path, noir_inputs: dict[str, object], witness_name: str) -> subprocess.CompletedProcess[str]:
    prover_toml = package_dir / "Prover.toml"
    original = prover_toml.read_text(encoding="utf-8") if prover_toml.exists() else None
    try:
        write_prover_toml(prover_toml, noir_inputs)
        return subprocess.run(
            [
                "nargo",
                "execute",
                "--overwrite-return",
                witness_name,
                "--program-dir",
                str(package_dir),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=_nargo_env(),
        )
    finally:
        if original is None:
            prover_toml.unlink(missing_ok=True)
        else:
            prover_toml.write_text(original, encoding="utf-8")
        (ROOT / "target" / f"{witness_name}.gz").unlink(missing_ok=True)


@pytest.mark.parametrize(
    "hash_name",
    ["keccak256", "poseidon2"],
)
def test_anchored_balance_prepare_and_generate_witness(hash_name: str) -> None:
    _, baseline, prepared, _ = _prepare_balance(hash_name)
    noir_inputs = to_noir_input_map(prepared)

    assert prepared.public_inputs["block_hash"].startswith("0x")
    assert prepared.public_inputs["state_root"] == baseline.state_root
    assert prepared.public_inputs["account_address"] == "0x6cc9397c3b38739dacbfaa68ead5f5d77ba5f455"
    assert prepared.public_inputs["hash_variant_id"] in (1, 2)
    if hash_name == "poseidon2":
        assert prepared.public_inputs["state_root_field"] == int(prepared.public_inputs["state_root"], 16)

    expected_prefix = [
        "public_block_hash",
        "public_state_root",
    ]
    if hash_name == "poseidon2":
        expected_prefix.append("public_state_root_field")
    expected_prefix += [
        "public_account_address",
        "public_claimed_balance_limbs",
        "public_hash_variant_id",
        "header_witness_version",
        "private_header_bytes",
        "private_header_len",
        "account_witness_version",
    ]
    assert list(noir_inputs)[: len(expected_prefix)] == expected_prefix

    parser = build_parser()
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "anchored_balance" / "Prover.toml"
        args = parser.parse_args(
            [
                "generate-witness",
                "--input",
                str(KECCAK_FIXTURE if hash_name == "keccak256" else POSEIDON2_FIXTURE),
                "--hash",
                hash_name,
                "--statement",
                "balance_verification_anchored" if hash_name == "keccak256" else "balance_verification_anchored_poseidon2",
                "--output",
                str(output_path),
            ]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = args.func(args)
        assert exit_code == 0, stdout.getvalue()
        generated = tomllib.loads(output_path.read_text(encoding="utf-8"))
        assert list(generated)[: len(expected_prefix)] == expected_prefix


@pytest.mark.parametrize(
    "hash_name",
    ["keccak256", "poseidon2"],
)
def test_anchored_codehash_prepare_and_generate_witness(hash_name: str) -> None:
    _, baseline, prepared, _ = _prepare_codehash(hash_name)
    noir_inputs = to_noir_input_map(prepared)

    assert prepared.public_inputs["block_hash"].startswith("0x")
    assert prepared.public_inputs["state_root"] == baseline.state_root
    assert prepared.public_inputs["account_address"] == "0x6cc9397c3b38739dacbfaa68ead5f5d77ba5f455"
    assert prepared.public_inputs["hash_variant_id"] in (1, 2)
    if hash_name == "poseidon2":
        assert prepared.public_inputs["state_root_field"] == int(prepared.public_inputs["state_root"], 16)

    expected_prefix = [
        "public_block_hash",
        "public_state_root",
    ]
    if hash_name == "poseidon2":
        expected_prefix.append("public_state_root_field")
    expected_prefix += [
        "public_account_address",
        "public_expected_code_hash",
        "public_hash_variant_id",
        "header_witness_version",
        "private_header_bytes",
        "private_header_len",
        "account_witness_version",
    ]
    assert list(noir_inputs)[: len(expected_prefix)] == expected_prefix

    parser = build_parser()
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "anchored_codehash" / "Prover.toml"
        args = parser.parse_args(
            [
                "generate-witness",
                "--input",
                str(KECCAK_FIXTURE if hash_name == "keccak256" else POSEIDON2_FIXTURE),
                "--hash",
                hash_name,
                "--statement",
                "codehash_verification_anchored" if hash_name == "keccak256" else "codehash_verification_anchored_poseidon2",
                "--output",
                str(output_path),
            ]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = args.func(args)
        assert exit_code == 0, stdout.getvalue()
        generated = tomllib.loads(output_path.read_text(encoding="utf-8"))
        assert list(generated)[: len(expected_prefix)] == expected_prefix


@pytest.mark.parametrize(
    ("hash_name", "statement_name", "mutator_name", "mutator"),
    [
        ("keccak256", "balance_verification_anchored", "wrong_public_block_hash", lambda inputs: inputs["public_block_hash"].__setitem__(0, inputs["public_block_hash"][0] ^ 1)),
        ("keccak256", "balance_verification_anchored", "wrong_public_state_root", lambda inputs: inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1)),
        ("keccak256", "balance_verification_anchored", "wrong_public_account_address", lambda inputs: inputs["public_account_address"].__setitem__(0, inputs["public_account_address"][0] ^ 1)),
        ("keccak256", "balance_verification_anchored", "wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
        ("keccak256", "balance_verification_anchored", "wrong_claimed_balance", lambda inputs: inputs["public_claimed_balance_limbs"].__setitem__(0, int(inputs["public_claimed_balance_limbs"][0]) + 1)),
        ("poseidon2", "balance_verification_anchored_poseidon2", "wrong_public_block_hash", lambda inputs: inputs["public_block_hash"].__setitem__(0, inputs["public_block_hash"][0] ^ 1)),
        ("poseidon2", "balance_verification_anchored_poseidon2", "wrong_public_state_root", lambda inputs: inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1)),
        ("poseidon2", "balance_verification_anchored_poseidon2", "wrong_public_state_root_field", lambda inputs: inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 1)),
        ("poseidon2", "balance_verification_anchored_poseidon2", "wrong_public_account_address", lambda inputs: inputs["public_account_address"].__setitem__(0, inputs["public_account_address"][0] ^ 1)),
        ("poseidon2", "balance_verification_anchored_poseidon2", "wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
        ("poseidon2", "balance_verification_anchored_poseidon2", "wrong_claimed_balance", lambda inputs: inputs["public_claimed_balance_limbs"].__setitem__(0, int(inputs["public_claimed_balance_limbs"][0]) + 1)),
    ],
)
def test_anchored_balance_positive_and_negative_execute(
    hash_name: str,
    statement_name: str,
    mutator_name: str,
    mutator,
) -> None:
    _, _, prepared, package_dir = _prepare_balance(hash_name)
    noir_inputs = to_noir_input_map(prepared)
    positive = _run_execute(package_dir, noir_inputs, f"{statement_name}_positive")
    assert positive.returncode == 0, positive.stdout + positive.stderr

    mutated = copy.deepcopy(noir_inputs)
    mutator(mutated)
    negative = _run_execute(package_dir, mutated, f"{statement_name}_{mutator_name}")
    assert negative.returncode != 0, negative.stdout + negative.stderr


@pytest.mark.parametrize(
    ("hash_name", "statement_name", "mutator_name", "mutator"),
    [
        ("keccak256", "codehash_verification_anchored", "wrong_public_block_hash", lambda inputs: inputs["public_block_hash"].__setitem__(0, inputs["public_block_hash"][0] ^ 1)),
        ("keccak256", "codehash_verification_anchored", "wrong_public_state_root", lambda inputs: inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1)),
        ("keccak256", "codehash_verification_anchored", "wrong_public_account_address", lambda inputs: inputs["public_account_address"].__setitem__(0, inputs["public_account_address"][0] ^ 1)),
        ("keccak256", "codehash_verification_anchored", "wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
        ("keccak256", "codehash_verification_anchored", "wrong_expected_code_hash", lambda inputs: inputs["public_expected_code_hash"].__setitem__(0, inputs["public_expected_code_hash"][0] ^ 1)),
        ("poseidon2", "codehash_verification_anchored_poseidon2", "wrong_public_block_hash", lambda inputs: inputs["public_block_hash"].__setitem__(0, inputs["public_block_hash"][0] ^ 1)),
        ("poseidon2", "codehash_verification_anchored_poseidon2", "wrong_public_state_root", lambda inputs: inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1)),
        ("poseidon2", "codehash_verification_anchored_poseidon2", "wrong_public_state_root_field", lambda inputs: inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 1)),
        ("poseidon2", "codehash_verification_anchored_poseidon2", "wrong_public_account_address", lambda inputs: inputs["public_account_address"].__setitem__(0, inputs["public_account_address"][0] ^ 1)),
        ("poseidon2", "codehash_verification_anchored_poseidon2", "wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
        ("poseidon2", "codehash_verification_anchored_poseidon2", "wrong_expected_code_hash", lambda inputs: inputs["public_expected_code_hash"].__setitem__(0, inputs["public_expected_code_hash"][0] ^ 1)),
    ],
)
def test_anchored_codehash_positive_and_negative_execute(
    hash_name: str,
    statement_name: str,
    mutator_name: str,
    mutator,
) -> None:
    _, _, prepared, package_dir = _prepare_codehash(hash_name)
    noir_inputs = to_noir_input_map(prepared)
    positive = _run_execute(package_dir, noir_inputs, f"{statement_name}_positive")
    assert positive.returncode == 0, positive.stdout + positive.stderr

    mutated = copy.deepcopy(noir_inputs)
    mutator(mutated)
    negative = _run_execute(package_dir, mutated, f"{statement_name}_{mutator_name}")
    assert negative.returncode != 0, negative.stdout + negative.stderr


def test_anchored_balance_codehash_source_sync_and_routing() -> None:
    from thesis_c.noir.artifacts import resolve_circuit_package

    anchored_balance_keccak = resolve_circuit_package("balance_verification_anchored", "keccak256", ROOT)
    anchored_balance_poseidon2 = resolve_circuit_package("balance_verification_anchored_poseidon2", "poseidon2", ROOT)
    anchored_codehash_keccak = resolve_circuit_package("codehash_verification_anchored", "keccak256", ROOT)
    anchored_codehash_poseidon2 = resolve_circuit_package("codehash_verification_anchored_poseidon2", "poseidon2", ROOT)

    assert anchored_balance_keccak.package_dir.name == "circuits_balance_anchored"
    assert anchored_balance_poseidon2.package_dir.name == "circuits_balance_anchored_poseidon2"
    assert anchored_codehash_keccak.package_dir.name == "circuits_codehash_anchored"
    assert anchored_codehash_poseidon2.package_dir.name == "circuits_codehash_anchored_poseidon2"
    assert anchored_codehash_poseidon2.nargo_package_name == "thesis_c_circuits_codehash_anchored_poseidon2"

    for anchored_dir, base_dir in [
        (ROOT / "circuits_balance_anchored" / "src", ROOT / "circuits_balance" / "src"),
        (ROOT / "circuits_balance_anchored_poseidon2" / "src", ROOT / "circuits_balance_poseidon2" / "src"),
        (ROOT / "circuits_codehash_anchored" / "src", ROOT / "circuits_codehash" / "src"),
        (ROOT / "circuits_codehash_anchored_poseidon2" / "src", ROOT / "circuits_codehash_poseidon2" / "src"),
    ]:
        assert (anchored_dir / "header_anchor.nr").exists()
        assert (anchored_dir / "header_fixtures.nr").exists()
        assert (anchored_dir / "expanded_header_capacity.nr").exists()
        assert (anchored_dir / "rlp.nr").exists()
        assert (anchored_dir / "header_anchor.nr").read_bytes() == (ROOT / "circuits_account_inclusion_anchored" / "src" / "header_anchor.nr").read_bytes()
        assert (anchored_dir / "header_fixtures.nr").read_bytes() == (ROOT / "circuits_account_inclusion_anchored" / "src" / "header_fixtures.nr").read_bytes()
        assert (anchored_dir / "expanded_header_capacity.nr").read_bytes() == (ROOT / "circuits_account_inclusion_anchored" / "src" / "expanded_header_capacity.nr").read_bytes()
        assert (anchored_dir / "rlp.nr").read_bytes() == (ROOT / "circuits_account_inclusion_anchored" / "src" / "rlp.nr").read_bytes()
