from __future__ import annotations

import json
from pathlib import Path

from thesis_c.cli import build_parser
from thesis_c.datasets.consistency import check_dataset_consistency
from thesis_c.datasets.discovery import discover_dataset
from thesis_c.datasets.manifest import (
    build_dataset_manifest,
    default_manifest_output_path,
    write_manifest,
)
from thesis_c.datasets.validation import validate_hash_variant, validate_metadata

FIXTURES_ROOT = Path(__file__).resolve().parent / "fixtures" / "datasets"
POSEIDON2_DATASET = FIXTURES_ROOT / "poseidon2"
KECCAK_DATASET = FIXTURES_ROOT / "keccak"


def _metadata_by_dataset_id(results):
    return {item.dataset_id: item for item in results}


def test_discovery_reports_files_and_payloads() -> None:
    context = discover_dataset(POSEIDON2_DATASET)
    assert context.report.missing_dataset is False
    assert len(context.report.files) == 2
    assert len(context.report.payloads) == 2
    assert {item.path for item in context.report.files} == {"invalid.json", "valid.json"}


def test_discovery_captures_file_load_errors(tmp_path: Path) -> None:
    dataset_dir = tmp_path / "dataset"
    dataset_dir.mkdir(parents=True, exist_ok=True)
    (dataset_dir / "broken.json").write_text("{", encoding="utf-8")

    context = discover_dataset(dataset_dir)
    assert len(context.report.errors) == 1
    assert "broken.json" in context.report.errors[0]
    assert context.report.files[0].errors


def test_metadata_validation_marks_valid_and_invalid_payloads() -> None:
    context = discover_dataset(POSEIDON2_DATASET)
    results = validate_metadata(context.payloads)
    by_id = _metadata_by_dataset_id(results)

    assert by_id["valid_0"].ok is True

    invalid = by_id["invalid_0"]
    assert invalid.ok is False
    assert "invalid_address_length" in invalid.errors
    assert "invalid_state_root_hex" in invalid.errors
    assert any(error.startswith("invalid_account_proof_hex:0") for error in invalid.errors)


def test_poseidon2_hash_validation_requires_environment(monkeypatch) -> None:
    monkeypatch.delenv("THESIS_C_POSEIDON2_CMD", raising=False)
    monkeypatch.delenv("THESIS_C_POSEIDON2_VECTORS", raising=False)

    context = discover_dataset(POSEIDON2_DATASET)
    metadata = validate_metadata(context.payloads)
    environment, results = validate_hash_variant(context.payloads, "poseidon2", metadata)

    assert environment.configured is False
    assert len(results) == 2
    assert all(item.adapter_configured is False for item in results)
    assert all(item.baseline_ok is None for item in results)


def test_keccak_hash_validation_runs_baseline() -> None:
    context = discover_dataset(KECCAK_DATASET)
    metadata = validate_metadata(context.payloads)
    environment, results = validate_hash_variant(context.payloads, "keccak256", metadata)

    assert environment.configured is True
    assert len(results) == 1
    assert results[0].adapter_configured is True
    assert results[0].baseline_ok in (True, False)


def test_consistency_checks_report_metadata_and_reference_findings() -> None:
    context = discover_dataset(POSEIDON2_DATASET)
    reference = discover_dataset(KECCAK_DATASET)
    metadata = validate_metadata(context.payloads)
    findings = check_dataset_consistency(context.report, metadata, reference.report)
    finding_codes = {item.code for item in findings}

    assert "metadata_validation_failed" in finding_codes
    assert "missing_block_number" in finding_codes
    assert "missing_reference_pair" in finding_codes


def test_manifest_generation_and_write(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("THESIS_C_POSEIDON2_CMD", raising=False)
    monkeypatch.delenv("THESIS_C_POSEIDON2_VECTORS", raising=False)

    manifest = build_dataset_manifest(
        dataset_path=POSEIDON2_DATASET,
        hash_name="poseidon2",
        reference_path=KECCAK_DATASET,
    )
    assert manifest.variant == "poseidon2"
    assert manifest.summary.total_files == 2
    assert manifest.summary.total_payloads == 2
    assert manifest.summary.has_errors is True

    output_path = tmp_path / "manifest.json"
    write_manifest(output_path, manifest)
    loaded = json.loads(output_path.read_text(encoding="utf-8"))
    assert loaded["variant"] == "poseidon2"
    assert loaded["summary"]["has_errors"] is True
    assert default_manifest_output_path(POSEIDON2_DATASET).name == "manifest.json"


def test_cli_parser_supports_dataset_subcommands() -> None:
    parser = build_parser()
    args = parser.parse_args(["dataset", "discover", "--path", str(POSEIDON2_DATASET)])
    assert args.command == "dataset"
    assert args.dataset_command == "discover"
