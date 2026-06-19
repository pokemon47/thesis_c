from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from thesis_c.datasets.consistency import check_dataset_consistency
from thesis_c.datasets.discovery import discover_dataset
from thesis_c.datasets.schema import DatasetManifest, ManifestSummary
from thesis_c.datasets.validation import validate_hash_variant, validate_metadata


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _build_summary(
    *,
    manifest: DatasetManifest,
) -> ManifestSummary:
    metadata_ok = sum(1 for item in manifest.metadata_validation if item.ok)
    metadata_errors = len(manifest.metadata_validation) - metadata_ok

    hash_ok = sum(1 for item in manifest.hash_validation if item.baseline_ok is True)
    hash_errors = len(manifest.hash_validation) - hash_ok
    if not manifest.hash_environment.configured:
        hash_errors = max(hash_errors, 1)

    consistency_errors = sum(
        1 for item in manifest.consistency_findings if item.level == "error"
    )
    consistency_warnings = sum(
        1 for item in manifest.consistency_findings if item.level == "warning"
    )

    discovery_errors = len(manifest.discovery.errors)
    if manifest.discovery.missing_dataset:
        discovery_errors += 1

    has_errors = any(
        (
            discovery_errors > 0,
            metadata_errors > 0,
            hash_errors > 0,
            consistency_errors > 0,
        )
    )

    return ManifestSummary(
        total_files=len(manifest.discovery.files),
        total_payloads=len(manifest.discovery.payloads),
        discovery_errors=discovery_errors,
        metadata_ok=metadata_ok,
        metadata_errors=metadata_errors,
        hash_ok=hash_ok,
        hash_errors=hash_errors,
        consistency_errors=consistency_errors,
        consistency_warnings=consistency_warnings,
        has_errors=has_errors,
    )


def build_dataset_manifest(
    dataset_path: str | Path,
    hash_name: str,
    reference_path: str | Path | None = None,
) -> DatasetManifest:
    discovery_context = discover_dataset(dataset_path)
    metadata_results = validate_metadata(discovery_context.payloads)
    hash_environment, hash_results = validate_hash_variant(
        discovery_context.payloads, hash_name, metadata_results
    )

    reference_root: str | None = None
    reference_discovery = None
    if reference_path:
        reference_context = discover_dataset(reference_path)
        reference_discovery = reference_context.report
        reference_root = reference_discovery.root

    consistency_findings = check_dataset_consistency(
        discovery_context.report,
        metadata_results,
        reference_discovery=reference_discovery,
    )

    manifest = DatasetManifest(
        generated_at=_utc_now(),
        variant=hash_name,
        root=discovery_context.report.root,
        reference_root=reference_root,
        discovery=discovery_context.report,
        hash_environment=hash_environment,
        metadata_validation=metadata_results,
        hash_validation=hash_results,
        consistency_findings=consistency_findings,
        summary=ManifestSummary(
            total_files=0,
            total_payloads=0,
            discovery_errors=0,
            metadata_ok=0,
            metadata_errors=0,
            hash_ok=0,
            hash_errors=0,
            consistency_errors=0,
            consistency_warnings=0,
            has_errors=False,
        ),
    )
    manifest.summary = _build_summary(manifest=manifest)
    return manifest


def default_manifest_output_path(dataset_path: str | Path) -> Path:
    target = Path(dataset_path)
    if target.is_dir():
        return target / "manifest.json"
    return target.parent / "manifest.json"


def write_manifest(path: str | Path, manifest: DatasetManifest) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target
