from __future__ import annotations

from dataclasses import dataclass

import rlp

from thesis_c.baseline.verifier_adapter import bytes_to_nibbles, decode_compact_with_flags
from thesis_c.hashes.base import HashVariant
from thesis_c.proof_inputs.normalizer import hex_to_bytes
from thesis_c.proof_inputs.schema import BaselineVerificationResult, ProofPayload, StorageProofEntry
from thesis_c.validation.models import (
    SEVERITY_ERROR,
    STATUS_FAIL,
    ValidationIssue,
)

EMPTY_STORAGE_ROOT = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"


@dataclass(slots=True)
class TrieWalkResult:
    status: str
    value: bytes | None
    error: str | None = None


def _issue(
    *,
    payload: ProofPayload,
    storage_key: str,
    code: str,
    message: str,
    node_index: int | None = None,
) -> ValidationIssue:
    return ValidationIssue(
        check="storage_proof_validation",
        scope="storage_proof",
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


def _quantity_to_int(value: str) -> int:
    text = value.strip().lower()
    if text.startswith("0x"):
        payload = text[2:] or "0"
        return int(payload, 16)
    if text.isdigit():
        return int(text, 10)
    raise ValueError(f"Invalid quantity value: {value}")


def _slot_key_to_32byte_key(slot_key: str) -> bytes:
    key_int = _quantity_to_int(slot_key)
    if key_int < 0:
        raise ValueError("Storage key quantity must be non-negative.")
    if key_int >= 2**256:
        raise ValueError("Storage key quantity exceeds 32-byte range.")
    return key_int.to_bytes(32, byteorder="big")


def _walk_mpt_proof(
    *,
    proof_nodes: list[bytes],
    key: bytes,
    expected_root: bytes,
    hash_variant: HashVariant,
) -> TrieWalkResult:
    path = bytes_to_nibbles(hash_variant.digest(key))
    path_index = 0
    current_hash = expected_root

    for node_rlp in proof_nodes:
        if hash_variant.digest(node_rlp) != current_hash:
            return TrieWalkResult(status="error", value=None, error="node_hash_mismatch")

        decoded = rlp.decode(node_rlp)
        if not isinstance(decoded, list):
            return TrieWalkResult(status="error", value=None, error="node_not_list")

        if len(decoded) == 17:
            if path_index == len(path):
                value = decoded[16]
                if not isinstance(value, (bytes, bytearray)) or len(value) == 0:
                    return TrieWalkResult(status="missing", value=None, error="branch_terminal_empty")
                return TrieWalkResult(status="found", value=bytes(value))

            nibble = path[path_index]
            child = decoded[nibble]
            if not isinstance(child, (bytes, bytearray)) or len(child) == 0:
                return TrieWalkResult(status="missing", value=None, error="branch_child_missing")

            child_bytes = bytes(child)
            if len(child_bytes) < 32:
                current_hash = hash_variant.digest(child_bytes)
            elif len(child_bytes) == 32:
                current_hash = child_bytes
            else:
                return TrieWalkResult(status="error", value=None, error="child_ref_too_large")

            path_index += 1
            continue

        if len(decoded) == 2:
            raw_path = decoded[0]
            raw_value = decoded[1]
            if not isinstance(raw_path, (bytes, bytearray)) or not isinstance(
                raw_value, (bytes, bytearray)
            ):
                return TrieWalkResult(status="error", value=None, error="short_node_not_bytes")

            node_path, is_leaf = decode_compact_with_flags(bytes(raw_path))
            for nibble in node_path:
                if path_index >= len(path) or path[path_index] != nibble:
                    return TrieWalkResult(status="missing", value=None, error="path_mismatch")
                path_index += 1

            value_bytes = bytes(raw_value)
            if is_leaf:
                if path_index != len(path):
                    return TrieWalkResult(status="missing", value=None, error="leaf_path_not_consumed")
                return TrieWalkResult(status="found", value=value_bytes)

            if len(value_bytes) == 0:
                return TrieWalkResult(status="missing", value=None, error="extension_child_missing")
            if len(value_bytes) < 32:
                current_hash = hash_variant.digest(value_bytes)
            elif len(value_bytes) == 32:
                current_hash = value_bytes
            else:
                return TrieWalkResult(status="error", value=None, error="extension_ref_too_large")
            continue

        return TrieWalkResult(status="error", value=None, error="unsupported_node_arity")

    return TrieWalkResult(status="missing", value=None, error="proof_exhausted")


def _decode_storage_leaf_value(value_bytes: bytes) -> int:
    decoded = rlp.decode(value_bytes)
    if not isinstance(decoded, (bytes, bytearray)):
        raise ValueError("Decoded storage value is not bytes.")
    if len(decoded) == 0:
        return 0
    return int.from_bytes(bytes(decoded), byteorder="big")


def _validate_single_storage_entry(
    *,
    payload: ProofPayload,
    baseline_result: BaselineVerificationResult,
    hash_variant: HashVariant,
    entry: StorageProofEntry,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    storage_key = entry.key

    try:
        expected_value = _quantity_to_int(entry.value)
    except Exception as exc:
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_value_parse_error",
                message=f"Failed to parse storage value quantity: {exc}",
            )
        )
        return issues

    if baseline_result.leaf is None:
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_missing_account_leaf",
                message="Cannot validate storage proof because account leaf is unavailable.",
            )
        )
        return issues

    try:
        slot_key_bytes = _slot_key_to_32byte_key(entry.key)
    except Exception as exc:
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_key_parse_error",
                message=f"Failed to parse storage key: {exc}",
            )
        )
        return issues

    expected_root_hex = baseline_result.leaf.storage_root.lower()
    if len(entry.proof) == 0 and expected_value == 0:
        if expected_root_hex == EMPTY_STORAGE_ROOT:
            return issues
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_empty_proof_requires_empty_root",
                message=(
                    "Empty storage proof with zero value is only allowed when account storageRoot "
                    "is the canonical empty trie root."
                ),
            )
        )
        return issues

    proof_nodes: list[bytes] = []
    for node_index, node_hex in enumerate(entry.proof):
        try:
            proof_nodes.append(hex_to_bytes(node_hex))
        except Exception as exc:
            issues.append(
                _issue(
                    payload=payload,
                    storage_key=storage_key,
                    code="storage_proof_hex_decode_error",
                    message=f"Failed to decode storage proof node hex: {exc}",
                    node_index=node_index,
                )
            )
            return issues

    try:
        expected_root = hex_to_bytes(baseline_result.leaf.storage_root)
    except Exception as exc:
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_root_decode_error",
                message=f"Failed to decode expected storage root: {exc}",
            )
        )
        return issues

    walk = _walk_mpt_proof(
        proof_nodes=proof_nodes,
        key=slot_key_bytes,
        expected_root=expected_root,
        hash_variant=hash_variant,
    )

    if walk.status == "error":
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_proof_walk_error",
                message=f"Storage proof walk failed: {walk.error}",
            )
        )
        return issues

    if walk.status == "missing":
        if expected_value != 0:
            issues.append(
                _issue(
                    payload=payload,
                    storage_key=storage_key,
                    code="storage_missing_nonzero_value",
                    message=(
                        "Storage proof resolves to missing slot, but expected value is non-zero "
                        f"({entry.value})."
                    ),
                )
            )
        return issues

    if walk.value is None:
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_proof_found_without_value",
                message="Storage proof walk reported found status but no terminal value bytes.",
            )
        )
        return issues

    try:
        observed_value = _decode_storage_leaf_value(walk.value)
    except Exception as exc:
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_leaf_value_decode_error",
                message=f"Failed to decode storage leaf value RLP: {exc}",
            )
        )
        return issues

    if observed_value != expected_value:
        issues.append(
            _issue(
                payload=payload,
                storage_key=storage_key,
                code="storage_value_mismatch",
                message=(
                    "Storage proof value mismatch: "
                    f"proof resolves to {hex(observed_value)} while payload value is {entry.value}."
                ),
            )
        )
    return issues


def validate_storage_proofs(
    *,
    payload: ProofPayload,
    baseline_result: BaselineVerificationResult,
    hash_variant: HashVariant,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for entry in payload.storage_proof:
        issues.extend(
            _validate_single_storage_entry(
                payload=payload,
                baseline_result=baseline_result,
                hash_variant=hash_variant,
                entry=entry,
            )
        )
    return issues
