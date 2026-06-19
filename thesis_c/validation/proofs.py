from __future__ import annotations

import rlp

from thesis_c.baseline.verifier_adapter import bounded_account_precheck, decode_compact_with_flags
from thesis_c.proof_inputs.normalizer import (
    MAX_ACCOUNT_NODE_BYTES,
    hex_to_bytes,
)
from thesis_c.proof_inputs.schema import ProofPayload
from thesis_c.validation.models import (
    SEVERITY_ERROR,
    STATUS_FAIL,
    ValidationIssue,
)


def _issue(
    *,
    payload: ProofPayload,
    code: str,
    message: str,
    scope: str,
    node_index: int | None = None,
    storage_key: str | None = None,
) -> ValidationIssue:
    return ValidationIssue(
        check="proof_shape_validation",
        scope=scope,
        status=STATUS_FAIL,
        severity=SEVERITY_ERROR,
        code=code,
        message=message,
        source_file=payload.source_file,
        source_index=payload.source_index,
        address=payload.address,
        block_number=payload.block_number,
        node_index=node_index,
        storage_key=storage_key,
    )


def _validate_mpt_node_shape(decoded_node: object, *, payload: ProofPayload, scope: str, node_index: int, storage_key: str | None) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    if not isinstance(decoded_node, list):
        issues.append(
            _issue(
                payload=payload,
                code="proof_node_not_list",
                message="RLP node must decode to a list.",
                scope=scope,
                node_index=node_index,
                storage_key=storage_key,
            )
        )
        return issues

    if len(decoded_node) not in (2, 17):
        issues.append(
            _issue(
                payload=payload,
                code="proof_node_unsupported_arity",
                message=f"MPT node list arity must be 2 or 17, got {len(decoded_node)}.",
                scope=scope,
                node_index=node_index,
                storage_key=storage_key,
            )
        )
        return issues

    if len(decoded_node) == 2:
        compact_path = decoded_node[0]
        value = decoded_node[1]
        if not isinstance(compact_path, (bytes, bytearray)):
            issues.append(
                _issue(
                    payload=payload,
                    code="proof_short_node_path_not_bytes",
                    message="Short MPT node compact path must be bytes.",
                    scope=scope,
                    node_index=node_index,
                    storage_key=storage_key,
                )
            )
        if not isinstance(value, (bytes, bytearray)):
            issues.append(
                _issue(
                    payload=payload,
                    code="proof_short_node_value_not_bytes",
                    message="Short MPT node value must be bytes.",
                    scope=scope,
                    node_index=node_index,
                    storage_key=storage_key,
                )
            )
        if isinstance(compact_path, (bytes, bytearray)):
            try:
                decode_compact_with_flags(bytes(compact_path))
            except Exception as exc:  # pragma: no cover - defensive decoding guard
                issues.append(
                    _issue(
                        payload=payload,
                        code="proof_compact_path_decode_error",
                        message=f"Failed to decode compact path flags: {exc}",
                        scope=scope,
                        node_index=node_index,
                        storage_key=storage_key,
                    )
                )

    return issues


def validate_proof_shapes(payload: ProofPayload) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []

    bounded_ok, bounded_error = bounded_account_precheck(payload)
    if not bounded_ok:
        issues.append(
            _issue(
                payload=payload,
                code="account_bounded_precheck_failed",
                message=f"Bounded account proof precheck failed: {bounded_error}",
                scope="account_proof",
            )
        )

    for node_index, node_hex in enumerate(payload.account_proof):
        try:
            node_bytes = hex_to_bytes(node_hex)
        except Exception as exc:
            issues.append(
                _issue(
                    payload=payload,
                    code="account_node_hex_decode_error",
                    message=f"Failed to decode account proof node hex: {exc}",
                    scope="account_proof",
                    node_index=node_index,
                )
            )
            continue

        if len(node_bytes) > MAX_ACCOUNT_NODE_BYTES:
            issues.append(
                _issue(
                    payload=payload,
                    code="account_node_too_large",
                    message=(
                        f"Account proof node size {len(node_bytes)} exceeds "
                        f"max bound {MAX_ACCOUNT_NODE_BYTES} bytes."
                    ),
                    scope="account_proof",
                    node_index=node_index,
                )
            )

        try:
            decoded = rlp.decode(node_bytes)
        except Exception as exc:
            issues.append(
                _issue(
                    payload=payload,
                    code="account_node_rlp_decode_error",
                    message=f"Failed to RLP-decode account proof node: {exc}",
                    scope="account_proof",
                    node_index=node_index,
                )
            )
            continue

        issues.extend(
            _validate_mpt_node_shape(
                decoded,
                payload=payload,
                scope="account_proof",
                node_index=node_index,
                storage_key=None,
            )
        )

    for entry in payload.storage_proof:
        for node_index, node_hex in enumerate(entry.proof):
            try:
                node_bytes = hex_to_bytes(node_hex)
            except Exception as exc:
                issues.append(
                    _issue(
                        payload=payload,
                        code="storage_node_hex_decode_error",
                        message=f"Failed to decode storage proof node hex: {exc}",
                        scope="storage_proof",
                        node_index=node_index,
                        storage_key=entry.key,
                    )
                )
                continue

            if len(node_bytes) == 0:
                issues.append(
                    _issue(
                        payload=payload,
                        code="storage_node_empty",
                        message="Storage proof node must not be empty.",
                        scope="storage_proof",
                        node_index=node_index,
                        storage_key=entry.key,
                    )
                )
                continue

            try:
                decoded = rlp.decode(node_bytes)
            except Exception as exc:
                issues.append(
                    _issue(
                        payload=payload,
                        code="storage_node_rlp_decode_error",
                        message=f"Failed to RLP-decode storage proof node: {exc}",
                        scope="storage_proof",
                        node_index=node_index,
                        storage_key=entry.key,
                    )
                )
                continue

            issues.extend(
                _validate_mpt_node_shape(
                    decoded,
                    payload=payload,
                    scope="storage_proof",
                    node_index=node_index,
                    storage_key=entry.key,
                )
            )

    return issues
