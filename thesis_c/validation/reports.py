from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from thesis_c.validation.models import (
    SEVERITY_INFO,
    STATUS_PASS,
    ValidationRecord,
    ValidationSummary,
)


def write_validation_json(
    path: str | Path,
    *,
    input_path: str,
    hash_name: str,
    summary: ValidationSummary,
    records: list[ValidationRecord],
) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input_path": input_path,
        "hash_name": hash_name,
        "summary": summary.to_dict(),
        "records": [record.to_dict() for record in records],
    }
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _base_csv_row(record: ValidationRecord) -> dict[str, Any]:
    return {
        "dataset_id": record.dataset_id,
        "source_file": record.source_file,
        "source_index": record.source_index,
        "address": record.address,
        "block_number": record.block_number,
        "account_proof_node_count": record.account_proof_node_count,
        "storage_proof_node_count": record.storage_proof_node_count,
        "raw_proof_byte_size": record.raw_proof_byte_size,
    }


def _record_ok_row(record: ValidationRecord) -> dict[str, Any]:
    row = _base_csv_row(record)
    row.update(
        {
            "check": "record_validation",
            "scope": "payload",
            "status": STATUS_PASS,
            "severity": SEVERITY_INFO,
            "code": "record_valid",
            "message": "Payload passed all configured validation checks.",
            "node_index": None,
            "storage_key": None,
        }
    )
    return row


def _issue_row(record: ValidationRecord, issue: dict[str, Any]) -> dict[str, Any]:
    row = _base_csv_row(record)
    row.update(
        {
            "check": issue.get("check"),
            "scope": issue.get("scope"),
            "status": issue.get("status"),
            "severity": issue.get("severity"),
            "code": issue.get("code"),
            "message": issue.get("message"),
            "node_index": issue.get("node_index"),
            "storage_key": issue.get("storage_key"),
        }
    )
    return row


def write_validation_csv(path: str | Path, records: list[ValidationRecord]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "dataset_id",
        "source_file",
        "source_index",
        "address",
        "block_number",
        "check",
        "scope",
        "status",
        "severity",
        "code",
        "message",
        "node_index",
        "storage_key",
        "account_proof_node_count",
        "storage_proof_node_count",
        "raw_proof_byte_size",
    ]

    rows: list[dict[str, Any]] = []
    for record in records:
        if not record.issues:
            rows.append(_record_ok_row(record))
            continue
        for issue in record.issues:
            rows.append(_issue_row(record, issue.to_dict()))

    with output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
