from __future__ import annotations

from collections import defaultdict

from thesis_c.datasets.schema import (
    ConsistencyFinding,
    DatasetDiscoveryReport,
    MetadataValidationResult,
)


def _sort_findings(findings: list[ConsistencyFinding]) -> list[ConsistencyFinding]:
    return sorted(
        findings,
        key=lambda item: (
            0 if item.level == "error" else 1,
            item.code,
            item.dataset_id or "",
            item.reference or "",
            item.message,
        ),
    )


def check_dataset_consistency(
    discovery: DatasetDiscoveryReport,
    metadata_results: list[MetadataValidationResult],
    reference_discovery: DatasetDiscoveryReport | None = None,
) -> list[ConsistencyFinding]:
    findings: list[ConsistencyFinding] = []

    if discovery.missing_dataset:
        findings.append(
            ConsistencyFinding(
                level="error",
                code="missing_dataset",
                message="Dataset path is empty or contains no JSON files.",
            )
        )

    for error in discovery.errors:
        findings.append(
            ConsistencyFinding(
                level="error",
                code="dataset_file_load_error",
                message=error,
            )
        )

    for file_record in discovery.files:
        if file_record.payload_count == 0 and not file_record.errors:
            findings.append(
                ConsistencyFinding(
                    level="warning",
                    code="empty_dataset_file",
                    message=f"File has zero payloads: {file_record.path}",
                )
            )

    by_dataset_id: dict[str, list[tuple[str, int]]] = defaultdict(list)
    by_logical_key: dict[tuple[str, int | None, int], list[str]] = defaultdict(list)

    for payload in discovery.payloads:
        by_dataset_id[payload.dataset_id].append((payload.source_file, payload.source_index))
        logical_key = (payload.address.lower(), payload.block_number, payload.source_index)
        by_logical_key[logical_key].append(payload.dataset_id)
        if payload.block_number is None:
            findings.append(
                ConsistencyFinding(
                    level="warning",
                    code="missing_block_number",
                    message="Payload is missing block number metadata.",
                    dataset_id=payload.dataset_id,
                )
            )

    for dataset_id, locations in by_dataset_id.items():
        if len(locations) <= 1:
            continue
        details = ", ".join(f"{source}:{index}" for source, index in sorted(locations))
        findings.append(
            ConsistencyFinding(
                level="error",
                code="duplicate_dataset_id",
                message=f"Dataset id appears multiple times: {details}",
                dataset_id=dataset_id,
            )
        )

    for logical_key, dataset_ids in by_logical_key.items():
        if len(dataset_ids) <= 1:
            continue
        findings.append(
            ConsistencyFinding(
                level="warning",
                code="duplicate_logical_key",
                message=(
                    "Multiple payloads share "
                    f"address={logical_key[0]} block_number={logical_key[1]} "
                    f"source_index={logical_key[2]}"
                ),
                reference=",".join(sorted(dataset_ids)),
            )
        )

    metadata_errors = [item for item in metadata_results if not item.ok]
    for item in metadata_errors:
        findings.append(
            ConsistencyFinding(
                level="error",
                code="metadata_validation_failed",
                message="Metadata validation failed for payload.",
                dataset_id=item.dataset_id,
                reference=";".join(item.errors),
            )
        )

    if reference_discovery is not None:
        target_keys = {
            (item.address.lower(), item.block_number): item.dataset_id
            for item in discovery.payloads
        }
        reference_keys = {
            (item.address.lower(), item.block_number): item.dataset_id
            for item in reference_discovery.payloads
        }

        for key in sorted(target_keys.keys() - reference_keys.keys()):
            findings.append(
                ConsistencyFinding(
                    level="warning",
                    code="missing_reference_pair",
                    message=(
                        "Target dataset key is missing from reference dataset: "
                        f"address={key[0]} block_number={key[1]}"
                    ),
                    dataset_id=target_keys[key],
                )
            )

        for key in sorted(reference_keys.keys() - target_keys.keys()):
            findings.append(
                ConsistencyFinding(
                    level="warning",
                    code="missing_target_pair",
                    message=(
                        "Reference dataset key is missing from target dataset: "
                        f"address={key[0]} block_number={key[1]}"
                    ),
                    reference=reference_keys[key],
                )
            )

    return _sort_findings(findings)
