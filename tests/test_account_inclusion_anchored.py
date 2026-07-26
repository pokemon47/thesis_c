from __future__ import annotations

import io
import os
import subprocess
import tempfile
from pathlib import Path
from contextlib import redirect_stdout
import tomllib

import pytest

from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.cli import build_parser
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.proof_inputs.header_anchor import (
    build_header_anchor_witness,
    load_default_header_anchor_fixtures,
)
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.proof_inputs.normalizer import compute_leaf_value_commitment
from thesis_c.statements.account_inclusion_anchored import AnchoredAccountInclusionStatement


ROOT = Path(__file__).resolve().parents[1]
THESIS_ROOT = ROOT.parents[1]
ANCHORED_PACKAGE = ROOT / "circuits_account_inclusion_anchored"
ANCHORED_PACKAGE_PROVER = ANCHORED_PACKAGE / "Prover.toml"
ANCHORED_FIXTURE = (
    ROOT / "datasets" / "keccak" / "hoodi_block_9_anchored_account_proof.json"
)


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
    hash_variant = Keccak256Hash()
    baseline_results = [verify_account_payload(payload, hash_variant) for payload in payloads]
    prepared = AnchoredAccountInclusionStatement().prepare(payloads, baseline_results)
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


def test_anchored_account_inclusion_prepare_and_cli_round_trip() -> None:
    payloads, baseline_results, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)

    assert prepared.public_inputs["hash_name"] == "keccak256"
    assert prepared.public_inputs["hash_variant_id"] == 1
    assert prepared.public_inputs["account_address"] == "0x6cc9397c3b38739dacbfaa68ead5f5d77ba5f455"
    assert prepared.public_inputs["block_hash"] == "0x83e24ce844bf933bcaa21088d6804f6a17bd21f6a6f26a66ecb22f236ce64430"
    assert prepared.public_inputs["state_root"] == baseline_results[0].state_root
    assert prepared.public_inputs["leaf_value_commitment"] == compute_leaf_value_commitment(
        baseline_results[0].leaf.nonce,
        baseline_results[0].leaf.balance,
        bytes.fromhex(baseline_results[0].leaf.storage_root[2:]),
        bytes.fromhex(baseline_results[0].leaf.code_hash[2:]),
    )

    assert list(noir_inputs)[:9] == [
        "public_block_hash",
        "public_state_root",
        "public_account_address",
        "public_hash_variant_id",
        "public_leaf_value_commitment",
        "header_witness_version",
        "private_header_bytes",
        "private_header_len",
        "account_witness_version",
    ]
    assert noir_inputs["public_block_hash"] == [int(b) for b in bytes.fromhex(prepared.public_inputs["block_hash"][2:])]
    assert noir_inputs["public_state_root"] == [int(b) for b in bytes.fromhex(prepared.public_inputs["state_root"][2:])]
    assert noir_inputs["public_account_address"] == [int(b) for b in bytes.fromhex(prepared.public_inputs["account_address"][2:])]
    assert noir_inputs["public_hash_variant_id"] == 1
    assert noir_inputs["public_leaf_value_commitment"] == prepared.public_inputs["leaf_value_commitment"]
    assert noir_inputs["header_witness_version"] == 1
    assert noir_inputs["account_witness_version"] == 1
    assert len(noir_inputs["private_header_bytes"]) == 640
    assert noir_inputs["private_header_len"] == 577
    assert all(byte == 0 for byte in noir_inputs["private_header_bytes"][577:])
    assert noir_inputs["private_active_node_count"] == prepared.private_inputs["account_proof_depth"]

    parser = build_parser()
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = Path(tmp_dir) / "anchored" / "Prover.toml"
        args = parser.parse_args(
            [
                "generate-witness",
                "--input",
                str(ANCHORED_FIXTURE),
                "--hash",
                "keccak256",
                "--statement",
                "account_inclusion_anchored",
                "--output",
                str(output_path),
            ]
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = args.func(args)

        assert exit_code == 0
        assert "Selected statement: account_inclusion_anchored" in stdout.getvalue()
        generated = tomllib.loads(output_path.read_text(encoding="utf-8"))
        assert list(generated)[:9] == list(noir_inputs)[:9]
        assert generated["public_block_hash"] == noir_inputs["public_block_hash"]
        assert generated["public_state_root"] == noir_inputs["public_state_root"]
        assert generated["header_witness_version"] == 1
        assert generated["account_witness_version"] == 1


def test_anchored_account_inclusion_nargo_execute_succeeds() -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    result = _run_anchored_execute(noir_inputs, "anchored_account_inclusion_smoke")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Circuit witness successfully solved" in result.stdout


@pytest.mark.parametrize(
    "mutator",
    [
        lambda inputs: inputs["public_block_hash"].__setitem__(0, inputs["public_block_hash"][0] ^ 1),
        lambda inputs: inputs["public_state_root"].__setitem__(0, inputs["public_state_root"][0] ^ 1),
        lambda inputs: inputs.__setitem__("public_leaf_value_commitment", int(inputs["public_leaf_value_commitment"]) + 1),
    ],
    ids=[
        "wrong_public_block_hash",
        "wrong_public_state_root",
        "wrong_public_leaf_value_commitment",
    ],
)
def test_anchored_account_inclusion_rejects_public_mutations(mutator) -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    mutator(noir_inputs)
    result = _run_anchored_execute(noir_inputs, "anchored_account_inclusion_mutated_public")

    assert result.returncode != 0
    assert result.stdout or result.stderr


def test_anchored_account_inclusion_rejects_header_state_root_mismatch() -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    alternate_fixture = load_default_header_anchor_fixtures()[0]
    alternate_witness = build_header_anchor_witness(alternate_fixture)
    noir_inputs["public_block_hash"] = alternate_witness["public_block_hash"]
    noir_inputs["private_header_bytes"] = alternate_witness["private_header_bytes"]
    noir_inputs["private_header_len"] = alternate_witness["private_header_len"]

    result = _run_anchored_execute(noir_inputs, "anchored_account_inclusion_header_root_mismatch")

    assert result.returncode != 0
    assert result.stdout or result.stderr


def test_anchored_account_inclusion_rejects_wrong_public_account_address() -> None:
    _, _, prepared = _prepared_statement()
    noir_inputs = to_noir_input_map(prepared)
    noir_inputs["public_account_address"][0] ^= 1

    result = _run_anchored_execute(noir_inputs, "anchored_account_inclusion_wrong_public_account_address")

    assert result.returncode != 0
    assert result.stdout or result.stderr


def test_anchored_account_inclusion_mechanical_sync_is_preserved() -> None:
    root = ROOT
    anchored = root / "circuits_account_inclusion_anchored" / "src"
    keccak = root / "circuits" / "src"
    standalone_header = root / "circuits_header_anchor" / "src"
    standalone_mpt = root / "circuits_mpt_inclusion" / "src"

    assert (anchored / "account_inclusion.nr").read_bytes() == (keccak / "account_inclusion.nr").read_bytes()
    assert (anchored / "account_commitment.nr").read_bytes() == (keccak / "account_commitment.nr").read_bytes()
    assert (anchored / "expanded_hash_keccak.nr").read_bytes() == (keccak / "expanded_hash_keccak.nr").read_bytes()
    assert (anchored / "expanded_mpt_capacity.nr").read_bytes() == (keccak / "expanded_mpt_capacity.nr").read_bytes()
    assert (anchored / "hash_keccak.nr").read_bytes() == (keccak / "hash_keccak.nr").read_bytes()
    assert (anchored / "mpt_simplified.nr").read_bytes() == (keccak / "mpt_simplified.nr").read_bytes()
    assert (anchored / "types.nr").read_bytes() == (keccak / "types.nr").read_bytes()
    assert (anchored / "types" / "rlp_account.nr").read_bytes() == (keccak / "types" / "rlp_account.nr").read_bytes()
    assert (anchored / "header_anchor.nr").read_bytes() == (standalone_header / "header_anchor.nr").read_bytes()
    assert (anchored / "expanded_header_capacity.nr").read_bytes() == (
        standalone_header / "expanded_header_capacity.nr"
    ).read_bytes()
    assert (anchored / "rlp.nr").read_bytes() == (standalone_header / "rlp.nr").read_bytes()

    anchored_mpt = (anchored / "expanded_account_verifier.nr").read_text()
    standalone_mpt_text = (standalone_mpt / "mpt_inclusion.nr").read_text()
    normalized = anchored_mpt.replace(
        "crate::expanded_hash_keccak::hash_node",
        "crate::hash_keccak::hash_node",
    )
    assert normalized == standalone_mpt_text
