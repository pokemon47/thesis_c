from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.proof_inputs.loaders import load_proof_file
from thesis_c.proof_inputs.normalizer import (
    account_proof_node_count,
    normalize_hex,
    raw_proof_byte_size,
    storage_proof_node_count,
)
from thesis_c.proof_inputs.schema import BaselineVerificationResult, ProofPayload
from thesis_c.validation.models import (
    SEVERITY_ERROR,
    SEVERITY_INFO,
    STATUS_FAIL,
    STATUS_SKIP,
    ValidationIssue,
    ValidationRecord,
    ValidationSummary,
    summarize_records,
)
from thesis_c.validation.proofs import validate_proof_shapes
from thesis_c.validation.schema import validate_raw_document
from thesis_c.validation.storage import validate_storage_proofs


@dataclass(slots=True)
class DatasetValidationConfig:
    input_path: Path
    hash_name: str


@dataclass(slots=True)
class DatasetValidationResult:
    records: list[ValidationRecord]
    summary: ValidationSummary


def _build_hash(name: str):
    if name == "keccak256":
        return Keccak256Hash()
    if name == "poseidon2":
        return Poseidon2Hash.from_environment()
    raise ValueError(f"Unsupported hash variant: {name}")


def _list_json_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.rglob("*.json"))
    raise FileNotFoundError(f"Path does not exist: {path}")


def _dataset_id(payload: ProofPayload) -> str:
    stem = Path(payload.source_file or "memory").stem
    index = payload.source_index if payload.source_index is not None else 0
    return f"{stem}_{index}"


def _schema_record(file_path: Path, source_index: int | None, issues: list[ValidationIssue]) -> ValidationRecord:
    suffix = str(source_index) if source_index is not None else "file"
    return ValidationRecord(
        dataset_id=f"{file_path.stem}_schema_{suffix}",
        source_file=str(file_path),
        source_index=source_index,
        address=None,
        block_number=None,
        account_proof_node_count=0,
        storage_proof_node_count=0,
        raw_proof_byte_size=0,
        checks_run=1,
        issues=issues,
    )


def _payload_record(payload: ProofPayload) -> ValidationRecord:
    return ValidationRecord(
        dataset_id=_dataset_id(payload),
        source_file=str(payload.source_file or ""),
        source_index=payload.source_index,
        address=payload.address,
        block_number=payload.block_number,
        account_proof_node_count=account_proof_node_count(payload),
        storage_proof_node_count=storage_proof_node_count(payload),
        raw_proof_byte_size=raw_proof_byte_size(payload),
    )


def _issue_for_payload(
    *,
    payload: ProofPayload,
    check: str,
    scope: str,
    status: str,
    severity: str,
    code: str,
    message: str,
) -> ValidationIssue:
    return ValidationIssue(
        check=check,
        scope=scope,
        status=status,
        severity=severity,
        code=code,
        message=message,
        source_file=payload.source_file,
        source_index=payload.source_index,
        address=payload.address,
        block_number=payload.block_number,
    )


def _parse_quantity(value: str) -> int:
    text = value.strip().lower()
    if text.startswith("0x"):
        return int(text[2:] or "0", 16)
    if text.isdigit():
        return int(text, 10)
    raise ValueError(f"Invalid numeric quantity: {value}")


def _validate_account_consistency(
    *,
    payload: ProofPayload,
    baseline_result: BaselineVerificationResult,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    if not baseline_result.ok or baseline_result.leaf is None:
        issues.append(
            _issue_for_payload(
                payload=payload,
                check="account_proof_validation",
                scope="account_proof",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="account_proof_verification_failed",
                message=(
                    "Baseline account proof verification failed: "
                    f"{baseline_result.error or 'unknown error'}"
                ),
            )
        )
        return issues

    try:
        payload_nonce = _parse_quantity(payload.nonce)
    except Exception as exc:
        issues.append(
            _issue_for_payload(
                payload=payload,
                check="account_payload_consistency",
                scope="account",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="account_nonce_parse_error",
                message=f"Failed to parse payload nonce: {exc}",
            )
        )
        payload_nonce = None

    try:
        payload_balance = _parse_quantity(payload.balance)
    except Exception as exc:
        issues.append(
            _issue_for_payload(
                payload=payload,
                check="account_payload_consistency",
                scope="account",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="account_balance_parse_error",
                message=f"Failed to parse payload balance: {exc}",
            )
        )
        payload_balance = None

    if payload_nonce is not None and payload_nonce != baseline_result.leaf.nonce:
        issues.append(
            _issue_for_payload(
                payload=payload,
                check="account_payload_consistency",
                scope="account",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="account_nonce_mismatch",
                message=(
                    f"Payload nonce {payload.nonce} does not match decoded account nonce "
                    f"{hex(baseline_result.leaf.nonce)}."
                ),
            )
        )

    if payload_balance is not None and payload_balance != baseline_result.leaf.balance:
        issues.append(
            _issue_for_payload(
                payload=payload,
                check="account_payload_consistency",
                scope="account",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="account_balance_mismatch",
                message=(
                    f"Payload balance {payload.balance} does not match decoded account balance "
                    f"{hex(baseline_result.leaf.balance)}."
                ),
            )
        )

    if normalize_hex(payload.storage_hash) != normalize_hex(baseline_result.leaf.storage_root):
        issues.append(
            _issue_for_payload(
                payload=payload,
                check="account_payload_consistency",
                scope="account",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="account_storage_root_mismatch",
                message=(
                    "Payload storageHash does not match storageRoot decoded from the account leaf."
                ),
            )
        )

    if normalize_hex(payload.code_hash) != normalize_hex(baseline_result.leaf.code_hash):
        issues.append(
            _issue_for_payload(
                payload=payload,
                check="account_payload_consistency",
                scope="account",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="account_code_hash_mismatch",
                message="Payload codeHash does not match codeHash decoded from the account leaf.",
            )
        )

    if payload.state_root:
        if normalize_hex(payload.state_root) != normalize_hex(baseline_result.state_root):
            issues.append(
                _issue_for_payload(
                    payload=payload,
                    check="account_payload_consistency",
                    scope="account",
                    status=STATUS_FAIL,
                    severity=SEVERITY_ERROR,
                    code="account_state_root_mismatch",
                    message=(
                        "Payload stateRoot does not match root derived from account proof nodes."
                    ),
                )
            )

    return issues


def _schema_error_records(file_path: Path, issues: list[ValidationIssue]) -> list[ValidationRecord]:
    grouped: dict[int | None, list[ValidationIssue]] = {}
    for issue in issues:
        grouped.setdefault(issue.source_index, []).append(issue)
    return [_schema_record(file_path, index, group) for index, group in grouped.items()]


def run_dataset_validation(config: DatasetValidationConfig) -> DatasetValidationResult:
    files = _list_json_files(config.input_path)
    if not files:
        raise ValueError(f"No JSON files found at: {config.input_path}")

    hash_variant = _build_hash(config.hash_name)
    records: list[ValidationRecord] = []

    for file_path in files:
        try:
            raw = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception as exc:
            issue = ValidationIssue(
                check="schema_validation",
                scope="schema",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="json_parse_error",
                message=f"Failed to parse JSON file: {exc}",
                source_file=str(file_path),
                source_index=None,
            )
            records.append(_schema_record(file_path, None, [issue]))
            continue

        schema_issues = validate_raw_document(raw, str(file_path))
        if schema_issues:
            records.extend(_schema_error_records(file_path, schema_issues))
            continue

        payloads = load_proof_file(file_path)
        if not payloads:
            issue = ValidationIssue(
                check="schema_validation",
                scope="schema",
                status=STATUS_FAIL,
                severity=SEVERITY_ERROR,
                code="schema_no_payloads",
                message="File is syntactically valid JSON but did not produce any proof payloads.",
                source_file=str(file_path),
                source_index=None,
            )
            records.append(_schema_record(file_path, None, [issue]))
            continue

        for payload in payloads:
            record = _payload_record(payload)

            record.checks_run += 1
            record.issues.extend(validate_proof_shapes(payload))

            baseline_result: BaselineVerificationResult | None = None
            record.checks_run += 1
            try:
                baseline_result = verify_account_payload(payload, hash_variant)
            except Exception as exc:
                record.issues.append(
                    _issue_for_payload(
                        payload=payload,
                        check="account_proof_validation",
                        scope="account_proof",
                        status=STATUS_FAIL,
                        severity=SEVERITY_ERROR,
                        code="account_proof_verifier_exception",
                        message=f"Account proof verification raised exception: {exc}",
                    )
                )

            if baseline_result is not None:
                record.issues.extend(
                    _validate_account_consistency(
                        payload=payload,
                        baseline_result=baseline_result,
                    )
                )

                if baseline_result.ok and baseline_result.leaf is not None:
                    record.checks_run += 1
                    record.issues.extend(
                        validate_storage_proofs(
                            payload=payload,
                            baseline_result=baseline_result,
                            hash_variant=hash_variant,
                        )
                    )
                elif payload.storage_proof:
                    record.issues.append(
                        _issue_for_payload(
                            payload=payload,
                            check="storage_proof_validation",
                            scope="storage_proof",
                            status=STATUS_SKIP,
                            severity=SEVERITY_INFO,
                            code="storage_validation_skipped_due_to_account_failure",
                            message=(
                                "Storage proof validation skipped because account proof "
                                "verification failed."
                            ),
                        )
                    )

            records.append(record)

    summary = summarize_records(records, files_scanned=len(files))
    return DatasetValidationResult(records=records, summary=summary)
