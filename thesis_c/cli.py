from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from thesis_c.baseline.verifier_adapter import (
    verify_account_payload,
    verify_storage_payload,
)
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.datasets.discovery import discover_dataset
from thesis_c.datasets.manifest import (
    build_dataset_manifest,
    default_manifest_output_path,
    write_manifest,
)
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.proof_inputs.loaders import load_proof_path


def _parse_list(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def _hash_from_name(name: str):
    if name == "keccak256":
        return Keccak256Hash()
    if name == "poseidon2":
        return Poseidon2Hash.from_environment()
    raise ValueError(f"Unsupported hash: {name}")


def generate_witness_command(args: argparse.Namespace) -> int:
    proof_path = Path(args.input)
    output_path = Path(args.output)

    payloads = load_proof_path(proof_path)
    if not payloads:
        print(f"No proof payloads loaded from {proof_path}")
        return 2

    try:
        hash_variant = _hash_from_name(args.hash)
    except ValueError as exc:
        print(f"Unsupported hash: {exc}")
        return 2

    print(f"Loaded payloads: {len(payloads)}")
    print(f"Selected hash: {args.hash}")

    baseline_results = []
    for index, payload in enumerate(payloads):
        result = verify_account_payload(payload, hash_variant)
        if not result.ok:
            print(f"Baseline verification failed for payload {index}: {result.error}")
            return 1
        baseline_results.append(result)

    statement = AccountInclusionStatement()
    prepared = statement.prepare(payloads, baseline_results)
    noir_inputs = to_noir_input_map(prepared)
    write_prover_toml(output_path, noir_inputs)

    print(f"Selected hash variant ID: {noir_inputs['public_hash_variant_id']}")
    print(f"Output path: {output_path}")
    print("Witness generation succeeded")
    return 0


def baseline_command(args: argparse.Namespace) -> int:
    payloads = load_proof_path(args.input)
    hash_variant = _hash_from_name(args.hash)
    rows = [verify_account_payload(payload, hash_variant) for payload in payloads]

    ok_count = sum(1 for row in rows if row.ok)
    print(f"Loaded proofs: {len(rows)}")
    print(f"Hash variant: {args.hash}")
    print(f"Baseline ok: {ok_count}/{len(rows)}")

    if args.output_json:
        out = Path(args.output_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = [asdict(row) for row in rows]
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote baseline report: {out}")

    return 0


def verify_storage_command(args: argparse.Namespace) -> int:
    payloads = load_proof_path(args.input)
    hash_variant = _hash_from_name(args.hash)
    rows = [verify_storage_payload(payload, hash_variant) for payload in payloads]

    ok_payloads = sum(1 for row in rows if row.ok)
    total_entries = sum(len(row.entries) for row in rows)
    ok_entries = sum(1 for row in rows for entry in row.entries if entry.ok)

    print(f"Loaded proofs: {len(rows)}")
    print(f"Hash variant: {args.hash}")
    print(f"Payloads ok: {ok_payloads}/{len(rows)}")
    print(f"Storage entries ok: {ok_entries}/{total_entries}")

    if args.output_json:
        out = Path(args.output_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = [asdict(row) for row in rows]
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote storage verification report: {out}")

    overall_ok = bool(rows) and all(row.ok for row in rows)
    return 0 if overall_ok else 1


def benchmark_command(args: argparse.Namespace) -> int:
    from thesis_c.benchmark.csv_writer import write_csv
    from thesis_c.benchmark.json_writer import write_json
    from thesis_c.benchmark.runner import BenchmarkConfig, run_benchmarks

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = Path(args.output_dir) if args.output_dir else Path("benchmarks/raw") / timestamp
    output_dir.mkdir(parents=True, exist_ok=True)

    config = BenchmarkConfig(
        input_path=Path(args.input),
        circuits_dir=Path(args.circuits_dir),
        output_dir=output_dir,
        hashes=_parse_list(args.hashes),
        backends=_parse_list(args.backends),
        statements=_parse_list(args.statements),
        input_path_keccak=Path(args.input_keccak) if args.input_keccak else None,
        input_path_poseidon2=Path(args.input_poseidon2) if args.input_poseidon2 else None,
        bb_binary=args.bb_binary,
        bb_oracle_hash=args.bb_oracle_hash,
    )
    rows = run_benchmarks(config)
    csv_path = output_dir / "benchmark.csv"
    json_path = output_dir / "benchmark.json"
    write_csv(csv_path, rows)
    write_json(json_path, rows)

    print(f"Rows: {len(rows)}")
    print(f"CSV: {csv_path}")
    print(f"JSON: {json_path}")
    return 0


def analyze_command(args: argparse.Namespace) -> int:
    from thesis_c.benchmark.analyze_results import analyze_command as run_analysis

    return run_analysis(args)


def validate_dataset_command(args: argparse.Namespace) -> int:
    from thesis_c.validation.reports import write_validation_csv, write_validation_json
    from thesis_c.validation.runner import DatasetValidationConfig, run_dataset_validation

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = (
        Path(args.output_dir)
        if args.output_dir
        else Path("validation/reports") / timestamp
    )
    output_dir.mkdir(parents=True, exist_ok=True)

    config = DatasetValidationConfig(
        input_path=Path(args.input),
        hash_name=args.hash,
    )

    try:
        result = run_dataset_validation(config)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Validation input error: {exc}")
        return 2
    except Exception as exc:
        print(f"Validation execution error: {exc}")
        return 2

    csv_path = output_dir / "validation.csv"
    json_path = output_dir / "validation.json"
    try:
        write_validation_csv(csv_path, result.records)
        write_validation_json(
            json_path,
            input_path=str(config.input_path),
            hash_name=config.hash_name,
            summary=result.summary,
            records=result.records,
        )
    except Exception as exc:
        print(f"Validation report write error: {exc}")
        return 2

    print(f"Files scanned: {result.summary.files_scanned}")
    print(f"Records: {result.summary.records_total}")
    print(f"Errors: {result.summary.error_count}")
    print(f"Warnings: {result.summary.warning_count}")
    print(f"CSV: {csv_path}")
    print(f"JSON: {json_path}")
    return 0 if result.summary.ok else 1


def _write_json(path: str, payload: object) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return out


def _print_dataset_summary(summary: dict[str, int | bool]) -> None:
    print(f"Files: {summary['total_files']}")
    print(f"Payloads: {summary['total_payloads']}")
    print(f"Discovery errors: {summary['discovery_errors']}")
    print(f"Metadata errors: {summary['metadata_errors']}")
    print(f"Hash errors: {summary['hash_errors']}")
    print(f"Consistency errors: {summary['consistency_errors']}")
    print(f"Consistency warnings: {summary['consistency_warnings']}")
    print(f"Has errors: {summary['has_errors']}")


def dataset_discover_command(args: argparse.Namespace) -> int:
    context = discover_dataset(args.path)
    report = context.report
    print(f"Dataset root: {report.root}")
    print(f"Files discovered: {len(report.files)}")
    print(f"Payloads discovered: {len(report.payloads)}")
    print(f"Missing dataset: {report.missing_dataset}")
    if report.errors:
        print(f"Discovery errors: {len(report.errors)}")

    if args.output_json:
        out = _write_json(args.output_json, asdict(report))
        print(f"Wrote discovery report: {out}")

    return 1 if report.missing_dataset or bool(report.errors) else 0


def dataset_validate_command(args: argparse.Namespace) -> int:
    manifest = build_dataset_manifest(
        dataset_path=args.path,
        hash_name=args.hash,
        reference_path=args.reference or None,
    )
    print(f"Dataset root: {manifest.root}")
    print(f"Variant: {manifest.variant}")
    _print_dataset_summary(
        {
            "total_files": manifest.summary.total_files,
            "total_payloads": manifest.summary.total_payloads,
            "discovery_errors": manifest.summary.discovery_errors,
            "metadata_errors": manifest.summary.metadata_errors,
            "hash_errors": manifest.summary.hash_errors,
            "consistency_errors": manifest.summary.consistency_errors,
            "consistency_warnings": manifest.summary.consistency_warnings,
            "has_errors": manifest.summary.has_errors,
        }
    )

    if args.output_json:
        out = _write_json(args.output_json, manifest.to_dict())
        print(f"Wrote dataset validation report: {out}")

    return 1 if manifest.summary.has_errors else 0


def dataset_manifest_command(args: argparse.Namespace) -> int:
    manifest = build_dataset_manifest(
        dataset_path=args.path,
        hash_name=args.hash,
        reference_path=args.reference or None,
    )
    output_path = (
        Path(args.output)
        if args.output
        else default_manifest_output_path(dataset_path=args.path)
    )
    out = write_manifest(output_path, manifest)
    print(f"Wrote dataset manifest: {out}")
    _print_dataset_summary(
        {
            "total_files": manifest.summary.total_files,
            "total_payloads": manifest.summary.total_payloads,
            "discovery_errors": manifest.summary.discovery_errors,
            "metadata_errors": manifest.summary.metadata_errors,
            "hash_errors": manifest.summary.hash_errors,
            "consistency_errors": manifest.summary.consistency_errors,
            "consistency_warnings": manifest.summary.consistency_warnings,
            "has_errors": manifest.summary.has_errors,
        }
    )
    return 1 if manifest.summary.has_errors else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="thesis-c",
        description="Thesis C benchmark pipeline (Noir + Barretenberg).",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    baseline = subparsers.add_parser("baseline", help="Run baseline proof verification.")
    baseline.add_argument("--input", required=True, help="Input proof file or directory.")
    baseline.add_argument(
        "--hash",
        default="keccak256",
        choices=("keccak256", "poseidon2"),
        help="Hash variant for baseline verification.",
    )
    baseline.add_argument(
        "--output-json",
        default="",
        help="Optional path to write baseline JSON report.",
    )
    baseline.set_defaults(func=baseline_command)

    generate_witness = subparsers.add_parser(
        "generate-witness",
        help="Generate a Prover.toml witness from verified account inclusion proofs.",
    )
    generate_witness.add_argument(
        "--input",
        required=True,
        help="Input proof file or directory.",
    )
    generate_witness.add_argument(
        "--hash",
        default="keccak256",
        choices=("keccak256", "poseidon2"),
        help="Hash variant for witness generation.",
    )
    generate_witness.add_argument(
        "--output",
        default="circuits/Prover.toml",
        help="Output path for the generated Prover.toml.",
    )
    generate_witness.set_defaults(func=generate_witness_command)

    verify_storage = subparsers.add_parser(
        "verify-storage",
        help="Verify storage proof entries against account leaf storage roots.",
    )
    verify_storage.add_argument(
        "--input", required=True, help="Input proof file or directory."
    )
    verify_storage.add_argument(
        "--hash",
        default="keccak256",
        choices=("keccak256", "poseidon2"),
        help="Hash variant for storage proof verification.",
    )
    verify_storage.add_argument(
        "--output-json",
        default="",
        help="Optional path to write storage verification JSON report.",
    )
    verify_storage.set_defaults(func=verify_storage_command)

    dataset = subparsers.add_parser(
        "dataset", help="Run dataset discovery, validation, and manifest generation."
    )
    dataset_subparsers = dataset.add_subparsers(dest="dataset_command", required=True)

    discover = dataset_subparsers.add_parser(
        "discover", help="Discover dataset files and payloads."
    )
    discover.add_argument(
        "--path",
        default="datasets/poseidon2",
        help="Dataset file or directory to inspect.",
    )
    discover.add_argument(
        "--output-json",
        default="",
        help="Optional path to write discovery report JSON.",
    )
    discover.set_defaults(func=dataset_discover_command)

    validate = dataset_subparsers.add_parser(
        "validate", help="Validate metadata, hash configuration, and dataset consistency."
    )
    validate.add_argument(
        "--path",
        default="datasets/poseidon2",
        help="Dataset file or directory to inspect.",
    )
    validate.add_argument(
        "--hash",
        default="poseidon2",
        choices=("keccak256", "poseidon2"),
        help="Hash variant for baseline hash validation.",
    )
    validate.add_argument(
        "--reference",
        default="",
        help="Optional reference dataset path for cross-variant checks.",
    )
    validate.add_argument(
        "--output-json",
        default="",
        help="Optional path to write validation report JSON.",
    )
    validate.set_defaults(func=dataset_validate_command)

    manifest = dataset_subparsers.add_parser(
        "manifest", help="Generate a dataset manifest artifact."
    )
    manifest.add_argument(
        "--path",
        default="datasets/poseidon2",
        help="Dataset file or directory to inspect.",
    )
    manifest.add_argument(
        "--hash",
        default="poseidon2",
        choices=("keccak256", "poseidon2"),
        help="Hash variant for baseline hash validation.",
    )
    manifest.add_argument(
        "--reference",
        default="",
        help="Optional reference dataset path for cross-variant checks.",
    )
    manifest.add_argument(
        "--output",
        default="",
        help="Optional output path for manifest JSON.",
    )
    manifest.set_defaults(func=dataset_manifest_command)

    benchmark = subparsers.add_parser("benchmark", help="Run benchmark matrix.")
    benchmark.add_argument("--input", required=True, help="Input proof file or directory.")
    benchmark.add_argument(
        "--input-keccak",
        default="",
        help="Optional keccak dataset path (overrides --input for keccak).",
    )
    benchmark.add_argument(
        "--input-poseidon2",
        default="",
        help="Optional poseidon2 dataset path. If missing/empty, poseidon rows are marked missing_dataset.",
    )
    benchmark.add_argument(
        "--circuits-dir",
        default="circuits",
        help="Path to Noir circuits project directory.",
    )
    benchmark.add_argument(
        "--output-dir",
        default="",
        help="Output directory for benchmark artifacts.",
    )
    benchmark.add_argument(
        "--hashes",
        default="keccak256,poseidon2",
        help="Comma-separated hash variants.",
    )
    benchmark.add_argument(
        "--backends",
        default="ultra_plonk,ultra_honk",
        help="Comma-separated Barretenberg backend variants.",
    )
    benchmark.add_argument(
        "--statements",
        default="account_inclusion",
        help="Comma-separated statement list.",
    )
    benchmark.add_argument(
        "--bb-binary",
        default="bb",
        help="Barretenberg CLI binary name/path.",
    )
    benchmark.add_argument(
        "--bb-oracle-hash",
        default="keccak",
        help="Oracle hash flag passed to bb.",
    )
    benchmark.set_defaults(func=benchmark_command)

    analyze = subparsers.add_parser(
        "analyze",
        help="Analyze benchmark outputs and generate summary reports.",
    )
    analyze.add_argument(
        "--input",
        default="benchmarks/raw",
        help=(
            "Comma-separated benchmark input paths. Each path may be a benchmark file, "
            "run directory, or parent directory containing multiple runs."
        ),
    )
    analyze.add_argument(
        "--output-dir",
        default="",
        help="Optional output report directory. Defaults to benchmarks/reports/<timestamp>.",
    )
    analyze.add_argument(
        "--include-status",
        default="ok",
        help="Comma-separated statuses to include in numeric stats, or 'all'.",
    )
    analyze.add_argument(
        "--metrics",
        default="",
        help="Optional comma-separated metric columns. Defaults to core benchmark metrics.",
    )
    analyze.add_argument(
        "--no-plots",
        action="store_true",
        help="Skip plot generation.",
    )
    analyze.set_defaults(func=analyze_command)

    validate_dataset = subparsers.add_parser(
        "validate-dataset",
        help="Validate eth_getProof dataset schema and proof integrity.",
    )
    validate_dataset.add_argument(
        "--input",
        required=True,
        help="Input proof file or directory.",
    )
    validate_dataset.add_argument(
        "--hash",
        default="keccak256",
        choices=("keccak256", "poseidon2"),
        help="Hash variant used when walking account/storage proofs.",
    )
    validate_dataset.add_argument(
        "--output-dir",
        default="",
        help="Output directory for validation report artifacts.",
    )
    validate_dataset.set_defaults(func=validate_dataset_command)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
