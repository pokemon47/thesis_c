from __future__ import annotations

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
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.proof_inputs.anchored_poseidon2_account_inclusion import (
    build_anchored_poseidon2_account_inclusion_witness,
)
from thesis_c.proof_inputs.header_anchor import (
    build_header_anchor_witness,
    load_default_header_anchor_fixtures,
)
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.statements.account_inclusion_anchored_poseidon2 import (
    AnchoredPoseidon2AccountInclusionStatement,
)


ROOT = Path(__file__).resolve().parents[1]
THESIS_ROOT = ROOT.parents[1]
ANCHORED_PACKAGE = ROOT / "circuits_account_inclusion_anchored_poseidon2"
ANCHORED_PACKAGE_PROVER = ANCHORED_PACKAGE / "Prover.toml"
ANCHORED_FIXTURE = ROOT / "datasets" / "poseidon2" / "hoodi_block_9_anchored_account_proof_poseidon2.json"
REFERENCE_HEADER_FIXTURE = ROOT / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json"
POSEIDON2_CMD = "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}"


def _nargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(THESIS_ROOT)
    env["XDG_CACHE_HOME"] = str(THESIS_ROOT / ".cache")
    env["NARGO_HOME"] = str(THESIS_ROOT / "nargo")
    return env


def _sample_payloads():
    return load_proof_path(ANCHORED_FIXTURE)


def _prepared_statement():
    payloads = _sample_payloads()
    os.environ.setdefault("THESIS_C_POSEIDON2_CMD", POSEIDON2_CMD)
    hash_variant = Poseidon2Hash.from_environment()
    baseline_results = [verify_account_payload(payload, hash_variant) for payload in payloads]
    prepared = AnchoredPoseidon2AccountInclusionStatement().prepare(payloads, baseline_results)
    return payloads, baseline_results, prepared


def _run_anchored_execute(noir_inputs: dict[str, object], witness_name: str) -> subprocess.CompletedProcess[str]:
    original = ANCHORED_PACKAGE_PROVER.read_text(encoding="utf-8") if ANCHORED_PACKAGE_PROVER.exists() else None
    try:
        write_prover_toml(ANCHORED_PACKAGE_PROVER, noir_inputs)
        return subprocess.run(
            [
                "nargo",
                "execute",
                witness_name,
                "--program-dir",
                str(ANCHORED_PACKAGE),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            env=_nargo_env(),
        )
    finally:
        if original is None:
            ANCHORED_PACKAGE_PROVER.unlink(missing_ok=True)
        else:
            ANCHORED_PACKAGE_PROVER.write_text(original, encoding="utf-8")
        (ROOT / "target" / f"{witness_name}.gz").unlink(missing_ok=True)


def test_anchored_poseidon2_account_inclusion_prepare_and_cli_round_trip() -> None:
    payloads, baseline_results, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)

    assert prepared.public_inputs["hash_name"] == "poseidon2"
    assert prepared.public_inputs["hash_variant_id"] == 2
    assert prepared.public_inputs["account_address"] == "0x6cc9397c3b38739dacbfaa68ead5f5d77ba5f455"
    assert prepared.public_inputs["block_hash"] == "0x1eae48676858f378939b84cacb7e1815776db05a505d3182f5677723e1b5a581"
    assert prepared.public_inputs["state_root"] == baseline_results[0].state_root
    assert prepared.public_inputs["state_root_field"] == int(
        prepared.public_inputs["state_root_field"]
    )

    assert list(noir_inputs)[:8] == [
        "public_block_hash",
        "public_state_root",
        "public_state_root_field",
        "public_account_address",
        "public_hash_variant_id",
        "header_witness_version",
        "private_header_bytes",
        "private_header_len",
    ]
    assert noir_inputs["public_block_hash"] == [int(b) for b in bytes.fromhex(prepared.public_inputs["block_hash"][2:])]
    assert noir_inputs["public_state_root"] == [int(b) for b in bytes.fromhex(prepared.public_inputs["state_root"][2:])]
    assert noir_inputs["public_state_root_field"] == prepared.public_inputs["state_root_field"]
    assert noir_inputs["public_account_address"] == [int(b) for b in bytes.fromhex(prepared.public_inputs["account_address"][2:])]
    assert noir_inputs["public_hash_variant_id"] == 2
    assert noir_inputs["header_witness_version"] == 1
    assert noir_inputs["account_witness_version"] == 1
    assert len(noir_inputs["private_header_bytes"]) == 640
    assert noir_inputs["private_header_len"] == 577
    assert all(byte == 0 for byte in noir_inputs["private_header_bytes"][577:])

    parser = build_parser()
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "anchored_poseidon2" / "Prover.toml"
        args = parser.parse_args(
            [
                "generate-witness",
                "--input",
                str(ANCHORED_FIXTURE),
                "--hash",
                "poseidon2",
                "--statement",
                "account_inclusion_anchored_poseidon2",
                "--output",
                str(output_path),
            ]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = args.func(args)

        assert exit_code == 0
        assert "Selected statement: account_inclusion_anchored_poseidon2" in stdout.getvalue()
        generated = tomllib.loads(output_path.read_text(encoding="utf-8"))
        assert list(generated)[:8] == list(noir_inputs)[:8]
        assert generated["public_block_hash"] == noir_inputs["public_block_hash"]
        assert generated["public_state_root"] == noir_inputs["public_state_root"]
    assert int(generated["public_state_root_field"]) == noir_inputs["public_state_root_field"]


def test_anchored_poseidon2_account_inclusion_nargo_execute_succeeds() -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    result = _run_anchored_execute(noir_inputs, "anchored_poseidon2_account_inclusion_smoke")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Circuit witness successfully solved" in result.stdout


@pytest.mark.parametrize(
    "mutator",
    [
        lambda inputs: inputs["public_block_hash"].__setitem__(0, inputs["public_block_hash"][0] ^ 1),
        lambda inputs: inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1),
        lambda inputs: inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 1),
        lambda inputs: inputs["public_account_address"].__setitem__(0, inputs["public_account_address"][0] ^ 1),
    ],
    ids=[
        "wrong_public_block_hash",
        "wrong_public_state_root",
        "wrong_public_state_root_field",
        "wrong_public_account_address",
    ],
)
def test_anchored_poseidon2_account_inclusion_rejects_public_mutations(mutator) -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    mutator(noir_inputs)
    result = _run_anchored_execute(noir_inputs, "anchored_poseidon2_account_inclusion_mutated_public")

    assert result.returncode != 0
    assert result.stdout or result.stderr


def test_anchored_poseidon2_account_inclusion_rejects_header_state_root_mismatch() -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    # Use the Keccak anchored header fixture as a valid but mismatched header witness.
    from thesis_c.proof_inputs.anchored_account_inclusion import header_anchor_fixture_from_result

    keccak_payload = load_proof_path(REFERENCE_HEADER_FIXTURE)[0]
    mismatched_fixture = header_anchor_fixture_from_result(keccak_payload.raw_result)
    mismatched_witness = build_header_anchor_witness(mismatched_fixture)
    noir_inputs["public_block_hash"] = mismatched_witness["public_block_hash"]
    noir_inputs["private_header_bytes"] = mismatched_witness["private_header_bytes"]
    noir_inputs["private_header_len"] = mismatched_witness["private_header_len"]

    result = _run_anchored_execute(noir_inputs, "anchored_poseidon2_account_inclusion_header_root_mismatch")

    assert result.returncode != 0
    assert result.stdout or result.stderr


@pytest.mark.parametrize(
    ("name", "mutator"),
    [
        ("wrong_public_block_hash", lambda inputs: inputs["public_block_hash"].__setitem__(0, inputs["public_block_hash"][0] ^ 1)),
        ("wrong_public_state_root", lambda inputs: inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1)),
        ("wrong_public_state_root_field", lambda inputs: inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 1)),
        (
            "wrong_root_pair",
            lambda inputs: (
                inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1),
                inputs.__setitem__("public_state_root_field", int(inputs["public_state_root_field"]) + 2),
            ),
        ),
        ("wrong_public_account_address", lambda inputs: inputs["public_account_address"].__setitem__(0, inputs["public_account_address"][0] ^ 1)),
        ("wrong_hash_variant", lambda inputs: inputs.__setitem__("public_hash_variant_id", int(inputs["public_hash_variant_id"]) + 1)),
    ],
    ids=[
        "wrong_public_block_hash",
        "wrong_public_state_root",
        "wrong_public_state_root_field",
        "wrong_root_pair",
        "wrong_public_account_address",
        "wrong_hash_variant",
    ],
)
def test_anchored_poseidon2_account_inclusion_rejects_required_public_mutations(name: str, mutator) -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    mutator(noir_inputs)
    result = _run_anchored_execute(noir_inputs, f"anchored_poseidon2_account_inclusion_{name}")

    assert result.returncode != 0, result.stdout + result.stderr


def test_anchored_poseidon2_account_inclusion_root_linkage_and_field_bridge_are_explicit() -> None:
    source = (ROOT / "circuits_account_inclusion_anchored_poseidon2" / "src" / "header_anchor.nr").read_text(encoding="utf-8")
    assert "assert(keccak256(private_header_bytes, header_len) == public_block_hash);" in source
    assert "state_root[j] = payload_byte(private_header_bytes, field, j);" in source
    assert "assert(expected_header_field_count() == 20);" in source

    statement_source = (ROOT / "thesis_c" / "statements" / "account_inclusion_anchored_poseidon2.py").read_text(encoding="utf-8")
    assert '"state_root_field"' in statement_source
    assert '"header_authentication": "in_circuit"' in statement_source
    assert '"block_hash_binding": "in_circuit"' in statement_source


def test_anchored_poseidon2_account_inclusion_source_synchronization_is_preserved() -> None:
    anchored = ROOT / "circuits_account_inclusion_anchored_poseidon2" / "src"
    standalone_header = ROOT / "circuits_header_anchor" / "src"
    poseidon2 = ROOT / "circuits_poseidon2" / "src"

    assert (anchored / "header_anchor.nr").read_bytes() == (standalone_header / "header_anchor.nr").read_bytes()
    assert (anchored / "header_fixtures.nr").read_bytes() == (standalone_header / "header_fixtures.nr").read_bytes()
    assert (anchored / "expanded_header_capacity.nr").read_bytes() == (standalone_header / "expanded_header_capacity.nr").read_bytes()
    assert (anchored / "rlp.nr").read_bytes() == (standalone_header / "rlp.nr").read_bytes()
    assert (anchored / "account_inclusion.nr").read_bytes() == (poseidon2 / "account_inclusion.nr").read_bytes()
    assert (anchored / "mpt_inclusion.nr").read_bytes() == (poseidon2 / "mpt_inclusion.nr").read_bytes()


def test_anchored_poseidon2_account_inclusion_artifact_routing_is_separate() -> None:
    from thesis_c.noir.artifacts import resolve_circuit_package

    p2 = resolve_circuit_package("account_inclusion", "poseidon2", ROOT)
    anchored = resolve_circuit_package("account_inclusion_anchored_poseidon2", "poseidon2", ROOT)

    assert p2.package_dir != anchored.package_dir
    assert p2.nargo_package_name != anchored.nargo_package_name
    assert p2.package_dir.name == "circuits_poseidon2"
    assert anchored.package_dir.name == "circuits_account_inclusion_anchored_poseidon2"


def test_anchored_poseidon2_account_inclusion_mechanical_sync_is_preserved() -> None:
    root = ROOT
    anchored = root / "circuits_account_inclusion_anchored_poseidon2" / "src"
    poseidon2 = root / "circuits_poseidon2" / "src"

    assert (anchored / "account_inclusion.nr").read_bytes() == (poseidon2 / "account_inclusion.nr").read_bytes()
    assert (anchored / "account_terminal.nr").read_bytes() == (poseidon2 / "account_terminal.nr").read_bytes()
    assert (anchored / "expanded_hash_poseidon2.nr").read_bytes() == (poseidon2 / "expanded_hash_poseidon2.nr").read_bytes()
    assert (anchored / "expanded_mpt_capacity.nr").read_bytes() == (poseidon2 / "expanded_mpt_capacity.nr").read_bytes()
    assert (anchored / "hash_poseidon2.nr").read_bytes() == (poseidon2 / "hash_poseidon2.nr").read_bytes()
    assert (anchored / "mpt_inclusion.nr").read_bytes() == (poseidon2 / "mpt_inclusion.nr").read_bytes()
    assert (anchored / "mpt_simplified.nr").read_bytes() == (poseidon2 / "mpt_simplified.nr").read_bytes()
    assert (anchored / "types.nr").read_bytes() == (poseidon2 / "types.nr").read_bytes()
    assert (anchored / "types" / "rlp_account.nr").read_bytes() == (poseidon2 / "types" / "rlp_account.nr").read_bytes()
