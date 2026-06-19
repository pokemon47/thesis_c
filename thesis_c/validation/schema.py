from __future__ import annotations

import re
from typing import Any

from thesis_c.validation.models import (
    SEVERITY_ERROR,
    STATUS_FAIL,
    ValidationIssue,
)

_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")

_REQUIRED_RESULT_FIELDS = (
    "address",
    "balance",
    "codeHash",
    "nonce",
    "storageHash",
    "accountProof",
    "storageProof",
)


def _make_issue(
    *,
    source_file: str,
    source_index: int | None,
    code: str,
    message: str,
    scope: str = "schema",
) -> ValidationIssue:
    return ValidationIssue(
        check="schema_validation",
        scope=scope,
        status=STATUS_FAIL,
        severity=SEVERITY_ERROR,
        code=code,
        message=message,
        source_file=source_file,
        source_index=source_index,
    )


def _is_hex_prefixed(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("0x")


def _is_hex_bytes(value: Any, *, byte_length: int | None = None) -> bool:
    if not _is_hex_prefixed(value):
        return False
    payload = value[2:]
    if not payload:
        return False
    if len(payload) % 2 != 0:
        return False
    if _HEX_PATTERN.fullmatch(payload) is None:
        return False
    if byte_length is not None and len(payload) != byte_length * 2:
        return False
    return True


def _is_hex_quantity(value: Any) -> bool:
    if not _is_hex_prefixed(value):
        return False
    payload = value[2:]
    return bool(payload) and _HEX_PATTERN.fullmatch(payload) is not None


def _validate_result_object(
    *,
    source_file: str,
    source_index: int | None,
    result_object: dict[str, Any],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    for field_name in _REQUIRED_RESULT_FIELDS:
        if field_name not in result_object:
            issues.append(
                _make_issue(
                    source_file=source_file,
                    source_index=source_index,
                    code="schema_missing_required_field",
                    message=f"Missing required field '{field_name}' in proof result object.",
                )
            )

    address = result_object.get("address")
    if address is not None and not _is_hex_bytes(address, byte_length=20):
        issues.append(
            _make_issue(
                source_file=source_file,
                source_index=source_index,
                code="schema_invalid_address",
                message="Field 'address' must be a 20-byte hex string.",
            )
        )

    balance = result_object.get("balance")
    if balance is not None and not _is_hex_quantity(balance):
        issues.append(
            _make_issue(
                source_file=source_file,
                source_index=source_index,
                code="schema_invalid_balance",
                message="Field 'balance' must be a hex quantity string.",
            )
        )

    nonce = result_object.get("nonce")
    if nonce is not None and not _is_hex_quantity(nonce):
        issues.append(
            _make_issue(
                source_file=source_file,
                source_index=source_index,
                code="schema_invalid_nonce",
                message="Field 'nonce' must be a hex quantity string.",
            )
        )

    code_hash = result_object.get("codeHash")
    if code_hash is not None and not _is_hex_bytes(code_hash, byte_length=32):
        issues.append(
            _make_issue(
                source_file=source_file,
                source_index=source_index,
                code="schema_invalid_code_hash",
                message="Field 'codeHash' must be a 32-byte hex string.",
            )
        )

    storage_hash = result_object.get("storageHash")
    if storage_hash is not None and not _is_hex_bytes(storage_hash, byte_length=32):
        issues.append(
            _make_issue(
                source_file=source_file,
                source_index=source_index,
                code="schema_invalid_storage_hash",
                message="Field 'storageHash' must be a 32-byte hex string.",
            )
        )

    state_root = result_object.get("stateRoot")
    if state_root is not None and not _is_hex_bytes(state_root, byte_length=32):
        issues.append(
            _make_issue(
                source_file=source_file,
                source_index=source_index,
                code="schema_invalid_state_root",
                message="Field 'stateRoot' must be a 32-byte hex string when provided.",
            )
        )

    account_proof = result_object.get("accountProof")
    if account_proof is not None:
        if not isinstance(account_proof, list):
            issues.append(
                _make_issue(
                    source_file=source_file,
                    source_index=source_index,
                    code="schema_invalid_account_proof_type",
                    message="Field 'accountProof' must be a list of RLP node hex strings.",
                )
            )
        else:
            if len(account_proof) == 0:
                issues.append(
                    _make_issue(
                        source_file=source_file,
                        source_index=source_index,
                        code="schema_empty_account_proof",
                        message="Field 'accountProof' must contain at least one node.",
                    )
                )
            for node_index, node_hex in enumerate(account_proof):
                if not _is_hex_bytes(node_hex):
                    issues.append(
                        _make_issue(
                            source_file=source_file,
                            source_index=source_index,
                            code="schema_invalid_account_proof_node",
                            message=(
                                f"Field 'accountProof[{node_index}]' must be an even-length hex string."
                            ),
                            scope="account_proof",
                        )
                    )

    storage_proof = result_object.get("storageProof")
    if storage_proof is not None:
        if not isinstance(storage_proof, list):
            issues.append(
                _make_issue(
                    source_file=source_file,
                    source_index=source_index,
                    code="schema_invalid_storage_proof_type",
                    message="Field 'storageProof' must be a list of storage proof entry objects.",
                )
            )
        else:
            for entry_index, entry in enumerate(storage_proof):
                if not isinstance(entry, dict):
                    issues.append(
                        _make_issue(
                            source_file=source_file,
                            source_index=source_index,
                            code="schema_invalid_storage_entry",
                            message=f"Field 'storageProof[{entry_index}]' must be an object.",
                            scope="storage_proof",
                        )
                    )
                    continue

                for required in ("key", "value", "proof"):
                    if required not in entry:
                        issues.append(
                            _make_issue(
                                source_file=source_file,
                                source_index=source_index,
                                code="schema_missing_storage_entry_field",
                                message=(
                                    f"Field 'storageProof[{entry_index}]' is missing required key '{required}'."
                                ),
                                scope="storage_proof",
                            )
                        )

                if "key" in entry and not _is_hex_quantity(entry["key"]):
                    issues.append(
                        _make_issue(
                            source_file=source_file,
                            source_index=source_index,
                            code="schema_invalid_storage_key",
                            message=f"Field 'storageProof[{entry_index}].key' must be a hex quantity string.",
                            scope="storage_proof",
                        )
                    )

                if "value" in entry and not _is_hex_quantity(entry["value"]):
                    issues.append(
                        _make_issue(
                            source_file=source_file,
                            source_index=source_index,
                            code="schema_invalid_storage_value",
                            message=f"Field 'storageProof[{entry_index}].value' must be a hex quantity string.",
                            scope="storage_proof",
                        )
                    )

                proof_nodes = entry.get("proof")
                if proof_nodes is not None:
                    if not isinstance(proof_nodes, list):
                        issues.append(
                            _make_issue(
                                source_file=source_file,
                                source_index=source_index,
                                code="schema_invalid_storage_entry_proof_type",
                                message=(
                                    f"Field 'storageProof[{entry_index}].proof' must be a list of hex strings."
                                ),
                                scope="storage_proof",
                            )
                        )
                    else:
                        for node_index, node_hex in enumerate(proof_nodes):
                            if not _is_hex_bytes(node_hex):
                                issues.append(
                                    _make_issue(
                                        source_file=source_file,
                                        source_index=source_index,
                                        code="schema_invalid_storage_proof_node",
                                        message=(
                                            "Field "
                                            f"'storageProof[{entry_index}].proof[{node_index}]' "
                                            "must be an even-length hex string."
                                        ),
                                        scope="storage_proof",
                                    )
                                )

    return issues


def _extract_block_number_issues(
    *,
    source_file: str,
    source_index: int | None,
    container: dict[str, Any],
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    candidates = [container.get("blockNumber"), container.get("block_number")]
    meta = container.get("meta")
    if isinstance(meta, dict):
        candidates.append(meta.get("blockNumber"))

    for value in candidates:
        if value is None:
            continue
        if isinstance(value, int) and value >= 0:
            return issues
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("0x") and _is_hex_quantity(text):
                return issues
            if text.isdigit():
                return issues
        issues.append(
            _make_issue(
                source_file=source_file,
                source_index=source_index,
                code="schema_invalid_block_number",
                message="Optional block number metadata must be a non-negative int or numeric string.",
            )
        )
        return issues

    return issues


def _unwrap_result_object(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    if "result" in item:
        result = item.get("result")
        if isinstance(result, dict):
            return result
        return None
    if "accountProof" in item:
        return item
    return None


def validate_raw_document(raw: Any, source_file: str) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    if isinstance(raw, list):
        if len(raw) == 0:
            issues.append(
                _make_issue(
                    source_file=source_file,
                    source_index=None,
                    code="schema_empty_array",
                    message="Dataset array is empty; expected one or more proof objects.",
                )
            )
            return issues
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                issues.append(
                    _make_issue(
                        source_file=source_file,
                        source_index=index,
                        code="schema_invalid_array_item",
                        message="Each array element must be an object.",
                    )
                )
                continue
            result = _unwrap_result_object(item)
            if result is None:
                issues.append(
                    _make_issue(
                        source_file=source_file,
                        source_index=index,
                        code="schema_invalid_object_shape",
                        message=(
                            "Object must either contain a 'result' object or be a bare proof result "
                            "with 'accountProof'."
                        ),
                    )
                )
                continue
            issues.extend(
                _validate_result_object(
                    source_file=source_file,
                    source_index=index,
                    result_object=result,
                )
            )
            issues.extend(
                _extract_block_number_issues(
                    source_file=source_file,
                    source_index=index,
                    container=item,
                )
            )
        return issues

    if isinstance(raw, dict):
        result = _unwrap_result_object(raw)
        if result is None:
            issues.append(
                _make_issue(
                    source_file=source_file,
                    source_index=0,
                    code="schema_invalid_root_object",
                    message=(
                        "Root object must either contain a 'result' object or be a bare proof "
                        "result with 'accountProof'."
                    ),
                )
            )
            return issues

        issues.extend(
            _validate_result_object(
                source_file=source_file,
                source_index=0,
                result_object=result,
            )
        )
        issues.extend(
            _extract_block_number_issues(
                source_file=source_file,
                source_index=0,
                container=raw,
            )
        )
        return issues

    issues.append(
        _make_issue(
            source_file=source_file,
            source_index=None,
            code="schema_invalid_root_type",
            message="Root JSON value must be either an object or an array.",
        )
    )
    return issues
