from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from thesis_c.backends import BACKEND_REGISTRY
from thesis_c.benchmark.metrics import BenchmarkRecord
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.package_manager import compile_and_execute
from thesis_c.noir.witness_writer import write_prover_toml
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.proof_inputs.normalizer import (
    account_proof_node_count,
    raw_proof_byte_size,
    storage_proof_node_count,
)
from thesis_c.proof_inputs.schema import BaselineVerificationResult, ProofPayload
from thesis_c.statements import STATEMENT_REGISTRY
from thesis_c.statements.account_inclusion import ACCOUNT_INCLUSION_VERIFICATION_METADATA
from thesis_c.baseline.verifier_adapter import verify_account_payload


@dataclass(slots=True)
class BenchmarkConfig:
    input_path: Path
    circuits_dir: Path
    output_dir: Path
    hashes: list[str]
    backends: list[str]
    statements: list[str]
    input_path_keccak: Path | None = None
    input_path_poseidon2: Path | None = None
    bb_binary: str = "bb"
    bb_oracle_hash: str = "keccak"


def _safe_id(raw: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", raw)


def _dataset_id(payloads: list[ProofPayload]) -> str:
    head = payloads[0]
    return f"{Path(head.source_file or 'memory').stem}_{head.source_index or 0}"


def _build_hash(name: str):
    if name == "keccak256":
        return Keccak256Hash()
    if name == "poseidon2":
        return Poseidon2Hash.from_environment()
    raise ValueError(f"Unsupported hash variant: {name}")


def _has_json_files(path: Path) -> bool:
    return path.exists() and any(path.rglob("*.json"))


def _resolve_hash_input_path(config: BenchmarkConfig, hash_name: str) -> Path | None:
    if hash_name == "keccak256":
        candidate = config.input_path_keccak or config.input_path
        return candidate if candidate.exists() else None

    if hash_name == "poseidon2":
        explicit = config.input_path_poseidon2
        if explicit is not None and explicit.exists():
            return explicit

        default_poseidon = Path("datasets/poseidon2")
        if _has_json_files(default_poseidon):
            return default_poseidon
        return None

    return None


def _build_backend(name: str, bb_binary: str, oracle_hash: str):
    backend_cls = BACKEND_REGISTRY.get(name)
    if backend_cls is None:
        raise ValueError(f"Unsupported backend: {name}")
    return backend_cls(binary=bb_binary, oracle_hash=oracle_hash)


def _iter_statement_samples(
    payloads: list[ProofPayload],
    baseline_results: list[BaselineVerificationResult],
    required_payloads: int,
) -> Iterable[tuple[list[ProofPayload], list[BaselineVerificationResult]]]:
    if required_payloads == 1:
        for payload, baseline in zip(payloads, baseline_results, strict=True):
            yield [payload], [baseline]
        return

    if required_payloads == 2:
        grouped: dict[str, list[tuple[ProofPayload, BaselineVerificationResult]]] = {}
        for payload, baseline in zip(payloads, baseline_results, strict=True):
            grouped.setdefault(payload.address.lower(), []).append((payload, baseline))

        for items in grouped.values():
            items.sort(key=lambda pair: pair[0].block_number or -1)
            for idx in range(len(items) - 1):
                left, right = items[idx], items[idx + 1]
                yield [left[0], right[0]], [left[1], right[1]]
        return

    raise ValueError(f"Unsupported required payload count: {required_payloads}")


def _extract_constraint_count(circuit_json: Path) -> int | None:
    try:
        data = json.loads(circuit_json.read_text(encoding="utf-8"))
    except Exception:
        return None

    candidate_keys = [
        "num_constraints",
        "constraint_count",
        "backend_constraints",
        "acir_opcodes",
    ]
    for key in candidate_keys:
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, int):
            return value
    return None


def _verification_metadata(statement: str) -> dict[str, str | None]:
    if statement == "account_inclusion":
        return dict(ACCOUNT_INCLUSION_VERIFICATION_METADATA)
    return {
        "branch_child_binding": None,
        "leaf_account_binding": None,
        "rlp_decoding": None,
        "mpt_verification_level": None,
    }


def _error_record(
    *,
    dataset_id: str,
    statement: str,
    hash_name: str,
    backend: str,
    payload: ProofPayload,
    baseline: BaselineVerificationResult,
    error: str,
) -> BenchmarkRecord:
    return BenchmarkRecord(
        dataset_id=dataset_id,
        statement=statement,
        hash_name=hash_name,
        backend=backend,
        address=payload.address,
        block_number=payload.block_number,
        proof_generation_time_s=0.0,
        proof_verification_time_s=0.0,
        witness_generation_time_s=0.0,
        compile_time_s=0.0,
        proof_size_bytes=0,
        prove_peak_memory_bytes=0,
        verify_peak_memory_bytes=0,
        circuit_size_bytes=None,
        constraint_count=None,
        account_proof_node_count=baseline.account_proof_node_count,
        storage_proof_node_count=baseline.storage_proof_node_count,
        raw_proof_byte_size=baseline.raw_proof_byte_size,
        verification_ok=False,
        **_verification_metadata(statement),
        status="error",
        error=error,
    )


def _template_row(
    *,
    dataset_id: str,
    statement: str,
    hash_name: str,
    backend: str,
    payload: ProofPayload,
    status: str,
    error: str,
) -> BenchmarkRecord:
    return BenchmarkRecord(
        dataset_id=dataset_id,
        statement=statement,
        hash_name=hash_name,
        backend=backend,
        address=payload.address,
        block_number=payload.block_number,
        proof_generation_time_s=0.0,
        proof_verification_time_s=0.0,
        witness_generation_time_s=0.0,
        compile_time_s=0.0,
        proof_size_bytes=0,
        prove_peak_memory_bytes=0,
        verify_peak_memory_bytes=0,
        circuit_size_bytes=None,
        constraint_count=None,
        account_proof_node_count=account_proof_node_count(payload),
        storage_proof_node_count=storage_proof_node_count(payload),
        raw_proof_byte_size=raw_proof_byte_size(payload),
        verification_ok=False,
        **_verification_metadata(statement),
        status=status,
        error=error,
    )


def run_benchmarks(config: BenchmarkConfig) -> list[BenchmarkRecord]:
    reference_payloads = load_proof_path(config.input_path)
    if not reference_payloads:
        raise ValueError("No proofs found in reference input path.")

    output_rows: list[BenchmarkRecord] = []
    for hash_name in config.hashes:
        hash_input_path = _resolve_hash_input_path(config, hash_name)
        if hash_input_path is None:
            for statement_name in config.statements:
                for backend_name in config.backends:
                    for payload in reference_payloads:
                        output_rows.append(
                            _template_row(
                                dataset_id=_dataset_id([payload]),
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                status="missing_dataset",
                                error="missing_dataset",
                            )
                        )
            continue

        payloads = load_proof_path(hash_input_path)
        if not payloads:
            for statement_name in config.statements:
                for backend_name in config.backends:
                    for payload in reference_payloads:
                        output_rows.append(
                            _template_row(
                                dataset_id=_dataset_id([payload]),
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                status="missing_dataset",
                                error="missing_dataset",
                            )
                        )
            continue

        # First-pass account inclusion circuit supports keccak only.
        if hash_name == "poseidon2" and "account_inclusion" in config.statements:
            for statement_name in config.statements:
                for backend_name in config.backends:
                    for payload in payloads:
                        status = "proxy" if statement_name == "account_inclusion" else "error"
                        reason = (
                            "proxy_hash_cost_poseidon2_not_in_circuit"
                            if statement_name == "account_inclusion"
                            else "statement_out_of_scope_for_current_task"
                        )
                        output_rows.append(
                            _template_row(
                                dataset_id=_dataset_id([payload]),
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                status=status,
                                error=reason,
                            )
                        )
            continue

        try:
            hash_variant = _build_hash(hash_name)
        except Exception as exc:
            for payload in payloads:
                output_rows.append(
                    BenchmarkRecord(
                        dataset_id=_dataset_id([payload]),
                        statement="n/a",
                        hash_name=hash_name,
                        backend="n/a",
                        address=payload.address,
                        block_number=payload.block_number,
                        proof_generation_time_s=0.0,
                        proof_verification_time_s=0.0,
                        witness_generation_time_s=0.0,
                        compile_time_s=0.0,
                        proof_size_bytes=0,
                        prove_peak_memory_bytes=0,
                        verify_peak_memory_bytes=0,
                        circuit_size_bytes=None,
                        constraint_count=None,
                        account_proof_node_count=len(payload.account_proof),
                        storage_proof_node_count=sum(
                            len(item.proof) for item in payload.storage_proof
                        ),
                        raw_proof_byte_size=raw_proof_byte_size(payload),
                        verification_ok=False,
                        **_verification_metadata("n/a"),
                        status="error",
                        error=f"Failed to initialize hash variant '{hash_name}': {exc}",
                    )
                )
            continue

        baselines = [verify_account_payload(payload, hash_variant) for payload in payloads]

        for statement_name in config.statements:
            if statement_name != "account_inclusion":
                for payload, baseline in zip(payloads, baselines, strict=True):
                    for backend_name in config.backends:
                        output_rows.append(
                            _error_record(
                                dataset_id=_dataset_id([payload]),
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                baseline=baseline,
                                error="statement_out_of_scope_for_current_task",
                            )
                        )
                continue

            statement_cls = STATEMENT_REGISTRY.get(statement_name)
            if statement_cls is None:
                for payload, baseline in zip(payloads, baselines, strict=True):
                    output_rows.append(
                        _error_record(
                            dataset_id=_dataset_id([payload]),
                            statement=statement_name,
                            hash_name=hash_name,
                            backend="n/a",
                            payload=payload,
                            baseline=baseline,
                            error=f"Unknown statement: {statement_name}",
                        )
                    )
                continue

            statement = statement_cls()
            for sample_payloads, sample_baselines in _iter_statement_samples(
                payloads, baselines, statement.required_payloads
            ):
                sample_id = _dataset_id(sample_payloads)
                for backend_name in config.backends:
                    payload = sample_payloads[0]
                    baseline = sample_baselines[0]
                    try:
                        prepared = statement.prepare(sample_payloads, sample_baselines)
                        noir_inputs = to_noir_input_map(prepared)
                        write_prover_toml(config.circuits_dir / "Prover.toml", noir_inputs)

                        artifacts = compile_and_execute(config.circuits_dir)
                        backend = _build_backend(
                            backend_name,
                            bb_binary=config.bb_binary,
                            oracle_hash=config.bb_oracle_hash,
                        )
                        run_dir = (
                            config.output_dir
                            / _safe_id(hash_name)
                            / _safe_id(backend_name)
                            / _safe_id(statement_name)
                            / _safe_id(sample_id)
                        )
                        backend_result = backend.prove_and_verify(
                            circuit_json=artifacts.circuit_json,
                            witness_gz=artifacts.witness_gz,
                            output_dir=run_dir,
                        )

                        output_rows.append(
                            BenchmarkRecord(
                                dataset_id=sample_id,
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                address=payload.address,
                                block_number=payload.block_number,
                                proof_generation_time_s=backend_result.prove_elapsed_s,
                                proof_verification_time_s=backend_result.verify_elapsed_s,
                                witness_generation_time_s=artifacts.execute_result.elapsed_s,
                                compile_time_s=artifacts.compile_result.elapsed_s,
                                proof_size_bytes=backend_result.proof_size_bytes,
                                prove_peak_memory_bytes=backend_result.prove_peak_memory_bytes,
                                verify_peak_memory_bytes=backend_result.verify_peak_memory_bytes,
                                circuit_size_bytes=artifacts.circuit_json.stat().st_size,
                                constraint_count=_extract_constraint_count(
                                    artifacts.circuit_json
                                ),
                                account_proof_node_count=baseline.account_proof_node_count,
                                storage_proof_node_count=baseline.storage_proof_node_count,
                                raw_proof_byte_size=baseline.raw_proof_byte_size,
                                verification_ok=backend_result.verification_ok,
                                **_verification_metadata(statement_name),
                                status="ok",
                                error=None,
                            )
                        )
                    except Exception as exc:
                        output_rows.append(
                            _error_record(
                                dataset_id=sample_id,
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                baseline=baseline,
                                error=str(exc),
                            )
                        )
    return output_rows
