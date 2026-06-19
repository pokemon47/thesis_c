from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

STATUS_FAIL = "fail"
STATUS_PASS = "pass"
STATUS_SKIP = "skip"


@dataclass(slots=True)
class ValidationIssue:
    check: str
    scope: str
    status: str
    severity: str
    code: str
    message: str
    source_file: str | None = None
    source_index: int | None = None
    address: str | None = None
    block_number: int | None = None
    node_index: int | None = None
    storage_key: str | None = None
    extras: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "check": self.check,
            "scope": self.scope,
            "status": self.status,
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "source_file": self.source_file,
            "source_index": self.source_index,
            "address": self.address,
            "block_number": self.block_number,
            "node_index": self.node_index,
            "storage_key": self.storage_key,
        }
        if self.extras:
            data["extras"] = dict(self.extras)
        return data


@dataclass(slots=True)
class ValidationRecord:
    dataset_id: str
    source_file: str
    source_index: int | None
    address: str | None
    block_number: int | None
    account_proof_node_count: int
    storage_proof_node_count: int
    raw_proof_byte_size: int
    checks_run: int = 0
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def issue_count(self) -> int:
        return len(self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == SEVERITY_ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == SEVERITY_WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == SEVERITY_INFO)

    @property
    def valid(self) -> bool:
        return self.error_count == 0

    @property
    def status(self) -> str:
        return "ok" if self.valid else "error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "source_file": self.source_file,
            "source_index": self.source_index,
            "address": self.address,
            "block_number": self.block_number,
            "account_proof_node_count": self.account_proof_node_count,
            "storage_proof_node_count": self.storage_proof_node_count,
            "raw_proof_byte_size": self.raw_proof_byte_size,
            "checks_run": self.checks_run,
            "issue_count": self.issue_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "status": self.status,
            "issues": [issue.to_dict() for issue in self.issues],
        }


@dataclass(slots=True)
class ValidationSummary:
    files_scanned: int
    records_total: int
    valid_records: int
    invalid_records: int
    issue_count: int
    error_count: int
    warning_count: int
    info_count: int

    @property
    def ok(self) -> bool:
        return self.error_count == 0

    def to_dict(self) -> dict[str, int | bool]:
        return {
            "files_scanned": self.files_scanned,
            "records_total": self.records_total,
            "valid_records": self.valid_records,
            "invalid_records": self.invalid_records,
            "issue_count": self.issue_count,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "ok": self.ok,
        }


def summarize_records(records: list[ValidationRecord], files_scanned: int) -> ValidationSummary:
    valid_records = sum(1 for record in records if record.valid)
    invalid_records = len(records) - valid_records
    issue_count = sum(record.issue_count for record in records)
    error_count = sum(record.error_count for record in records)
    warning_count = sum(record.warning_count for record in records)
    info_count = sum(record.info_count for record in records)
    return ValidationSummary(
        files_scanned=files_scanned,
        records_total=len(records),
        valid_records=valid_records,
        invalid_records=invalid_records,
        issue_count=issue_count,
        error_count=error_count,
        warning_count=warning_count,
        info_count=info_count,
    )
