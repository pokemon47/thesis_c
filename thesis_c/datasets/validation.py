from __future__ import annotations

import os
import re
from pathlib import Path

from thesis_c.baseline.verifier_adapter import bounded_account_precheck, verify_account_payload
from thesis_c.datasets.discovery import DiscoveredPayload
from thesis_c.datasets.schema import (
    HashEnvironmentStatus,
    HashValidationResult,
    MetadataValidationResult,
)
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.hashes.test_vectors import load_test_vectors

_HEX_RE = re.compile(r"^0x[0-9a-fA-F]*$")


def _record_key(source_file: str, source_index: int) -> tuple[str, int]:
    return (source_file, source_index)


def _is_hex(value: str) -> bool:
    return bool(_HEX_RE.fullmatch(value))


def _build_hash_variant(name: str):
    if name == "keccak256":
        return Keccak256Hash()
    if name == "poseidon2":
        return Poseidon2Hash.from_environment()
    raise ValueError(f"Unsupported hash variant: {name}")


def validate_metadata(payloads: list[DiscoveredPayload]) -> list[MetadataValidationResult]:
    results: list[MetadataValidationResult] = []
    for entry in payloads:
        record = entry.record
        payload = entry.payload
        errors: list[str] = []
        warnings: list[str] = []

        if not _is_hex(payload.address):
            errors.append("invalid_address_hex")
        elif len(payload.address) != 42:
            errors.append("invalid_address_length")

        if not payload.account_proof:
            errors.append("missing_account_proof")
        else:
            for idx, node_hex in enumerate(payload.account_proof):
                if not isinstance(node_hex, str) or not _is_hex(node_hex):
                    errors.append(f"invalid_account_proof_hex:{idx}")

        if payload.state_root is not None and not _is_hex(payload.state_root):
            errors.append("invalid_state_root_hex")
        if payload.state_root is None:
            warnings.append("missing_state_root")

        if payload.block_number is None:
            warnings.append("missing_block_number")
        elif payload.block_number < 0:
            errors.append("negative_block_number")

        bounded_ok = False
        bounded_error: str | None = None
        try:
            bounded_ok, bounded_error = bounded_account_precheck(payload)
        except Exception as exc:  # pragma: no cover - defensive guard
            bounded_ok = False
            bounded_error = f"bounded_precheck_exception:{exc}"

        if not bounded_ok:
            errors.append(f"bounded_precheck:{bounded_error or 'unknown'}")

        result = MetadataValidationResult(
            dataset_id=record.dataset_id,
            source_file=record.source_file,
            source_index=record.source_index,
            ok=not errors and bounded_ok,
            bounded_ok=bounded_ok,
            bounded_error=bounded_error,
            errors=sorted(errors),
            warnings=sorted(warnings),
        )
        results.append(result)

    return sorted(results, key=lambda item: (item.source_file, item.source_index))


def build_hash_environment_status(hash_name: str) -> HashEnvironmentStatus:
    if hash_name == "keccak256":
        return HashEnvironmentStatus(
            hash_name=hash_name,
            configured=True,
            command_template_present=False,
            vectors_env_path=None,
            vectors_loaded=False,
            vector_count=0,
            error=None,
        )

    if hash_name != "poseidon2":
        return HashEnvironmentStatus(
            hash_name=hash_name,
            configured=False,
            command_template_present=False,
            vectors_env_path=None,
            vectors_loaded=False,
            vector_count=0,
            error=f"unsupported_hash_variant:{hash_name}",
        )

    command_template = os.getenv("THESIS_C_POSEIDON2_CMD")
    vectors_env = os.getenv("THESIS_C_POSEIDON2_VECTORS")
    vectors_loaded = False
    vector_count = 0
    error: str | None = None

    if vectors_env:
        vector_path = Path(vectors_env)
        if not vector_path.exists():
            error = f"poseidon2_vectors_file_missing:{vector_path}"
        else:
            try:
                vectors = load_test_vectors(vector_path)
            except Exception as exc:
                error = f"poseidon2_vectors_load_error:{exc}"
            else:
                vectors_loaded = True
                vector_count = len(vectors)

    configured = bool(command_template) or vector_count > 0
    if not configured and error is None:
        error = (
            "poseidon2_not_configured:"
            "set THESIS_C_POSEIDON2_CMD or THESIS_C_POSEIDON2_VECTORS"
        )

    return HashEnvironmentStatus(
        hash_name=hash_name,
        configured=configured,
        command_template_present=bool(command_template),
        vectors_env_path=vectors_env,
        vectors_loaded=vectors_loaded,
        vector_count=vector_count,
        error=error,
    )


def validate_hash_variant(
    payloads: list[DiscoveredPayload],
    hash_name: str,
    metadata_results: list[MetadataValidationResult],
) -> tuple[HashEnvironmentStatus, list[HashValidationResult]]:
    metadata_by_key = {
        _record_key(item.source_file, item.source_index): item for item in metadata_results
    }
    environment = build_hash_environment_status(hash_name)
    results: list[HashValidationResult] = []

    if not environment.configured:
        for entry in payloads:
            record = entry.record
            results.append(
                HashValidationResult(
                    dataset_id=record.dataset_id,
                    source_file=record.source_file,
                    source_index=record.source_index,
                    hash_name=hash_name,
                    adapter_configured=False,
                    baseline_ok=None,
                    error=environment.error or "hash_adapter_not_configured",
                )
            )
        return environment, sorted(results, key=lambda item: (item.source_file, item.source_index))

    try:
        hash_variant = _build_hash_variant(hash_name)
    except Exception as exc:
        environment.configured = False
        environment.error = f"hash_variant_init_error:{exc}"
        for entry in payloads:
            record = entry.record
            results.append(
                HashValidationResult(
                    dataset_id=record.dataset_id,
                    source_file=record.source_file,
                    source_index=record.source_index,
                    hash_name=hash_name,
                    adapter_configured=False,
                    baseline_ok=None,
                    error=environment.error,
                )
            )
        return environment, sorted(results, key=lambda item: (item.source_file, item.source_index))

    for entry in payloads:
        record = entry.record
        metadata = metadata_by_key.get(_record_key(record.source_file, record.source_index))
        if metadata is not None and not metadata.ok:
            results.append(
                HashValidationResult(
                    dataset_id=record.dataset_id,
                    source_file=record.source_file,
                    source_index=record.source_index,
                    hash_name=hash_name,
                    adapter_configured=True,
                    baseline_ok=None,
                    error="skipped_metadata_validation_failed",
                )
            )
            continue

        try:
            baseline = verify_account_payload(entry.payload, hash_variant)
        except Exception as exc:
            results.append(
                HashValidationResult(
                    dataset_id=record.dataset_id,
                    source_file=record.source_file,
                    source_index=record.source_index,
                    hash_name=hash_name,
                    adapter_configured=True,
                    baseline_ok=False,
                    error=f"baseline_exception:{exc}",
                )
            )
            continue

        results.append(
            HashValidationResult(
                dataset_id=record.dataset_id,
                source_file=record.source_file,
                source_index=record.source_index,
                hash_name=hash_name,
                adapter_configured=True,
                baseline_ok=baseline.ok,
                state_root=baseline.state_root,
                account_proof_node_count=baseline.account_proof_node_count,
                storage_proof_node_count=baseline.storage_proof_node_count,
                raw_proof_byte_size=baseline.raw_proof_byte_size,
                error=baseline.error,
            )
        )

    return environment, sorted(results, key=lambda item: (item.source_file, item.source_index))
