from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from thesis_c.backends import BACKEND_REGISTRY
from thesis_c.benchmark.metrics import BenchmarkRecord
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.noir.artifacts import (
    build_run_dir,
    build_run_identity,
    create_run_dir,
    relative_or_str,
    resolve_circuit_package,
    safe_filename,
    sha256_bytes,
    sha256_file,
    utc_timestamp,
    write_json,
)
from thesis_c.noir.package_manager import compile_isolated, execute_witness_isolated
from thesis_c.noir.witness_writer import render_prover_toml
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
    artifact_root: Path = Path("artifacts")


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


def _command_version(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    output = (completed.stdout + completed.stderr).strip()
    return output or None


def _source_proof_sha256(payload: ProofPayload) -> str:
    if not payload.source_file:
        return ""
    path = Path(payload.source_file)
    if not path.exists() or not path.is_file():
        return ""
    return sha256_file(path)


def _stable_source_proof_id(payload: ProofPayload, repo_root: Path) -> str:
    if not payload.source_file:
        return "memory"
    path = Path(payload.source_file)
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return path.name


def _backend_scheme(backend) -> str:
    return getattr(getattr(backend, "config", None), "scheme", backend.name)


def _write_run_metadata(
    *,
    path: Path,
    repo_root: Path,
    status: str,
    error: str | None,
    failed_phase: str | None,
    error_type: str | None,
    error_message: str | None,
    statement_name: str,
    hash_name: str,
    dataset_id: str,
    payload: ProofPayload,
    circuit_package,
    backend,
    oracle_hash: str,
    run_identity,
    package_prover_toml: Path,
    run_prover_toml: Path,
    witness_name: str | None,
    circuit_json: Path | None,
    witness_gz: Path | None,
    source_circuit_json: Path | None,
    source_witness_gz: Path | None,
    vk_path: Path | None,
    proof_path: Path | None,
    public_inputs_path: Path | None,
    timings_path: Path | None,
    timings: dict[str, int | float] | None,
    backend_result,
    poseidon2_command_template: str | None,
) -> None:
    def _hash_if_exists(path_value: Path | None) -> str | None:
        return sha256_file(path_value) if path_value is not None and path_value.exists() else None

    vk_hash_path = vk_path.parent / "vk_hash" if vk_path is not None else None
    file_hashes = {
        "package_prover_toml": _hash_if_exists(package_prover_toml),
        "prover_toml": _hash_if_exists(run_prover_toml),
        "circuit_json": _hash_if_exists(circuit_json),
        "witness_gz": _hash_if_exists(witness_gz),
        "vk": _hash_if_exists(vk_path),
        "vk_hash": _hash_if_exists(vk_hash_path),
        "proof": _hash_if_exists(proof_path),
        "public_inputs": _hash_if_exists(public_inputs_path),
        "timings": _hash_if_exists(timings_path),
    }
    file_hashes = {key: value for key, value in file_hashes.items() if value is not None}

    payload_path = Path(payload.source_file) if payload.source_file else Path("memory")
    metadata = {
        "artifact_paths": {
            "circuit_json": relative_or_str(circuit_json, repo_root) if circuit_json else None,
            "circuit_source": (
                relative_or_str(source_circuit_json, repo_root)
                if source_circuit_json is not None
                else None
            ),
            "package_prover_toml": relative_or_str(package_prover_toml, repo_root),
            "proof": relative_or_str(proof_path, repo_root) if proof_path else None,
            "public_inputs": (
                relative_or_str(public_inputs_path, repo_root)
                if public_inputs_path is not None
                else None
            ),
            "run_prover_toml": relative_or_str(run_prover_toml, repo_root),
            "timings": relative_or_str(timings_path, repo_root) if timings_path else None,
            "vk": relative_or_str(vk_path, repo_root) if vk_path else None,
            "witness": relative_or_str(witness_gz, repo_root) if witness_gz else None,
            "witness_source": (
                relative_or_str(source_witness_gz, repo_root)
                if source_witness_gz is not None
                else None
            ),
        },
        "backend": backend.name,
        "bb_version": _command_version([backend.config.binary, "--version"]),
        "created_timestamp": utc_timestamp(),
        "dataset_id": dataset_id,
        "error": error,
        "error_message": error_message,
        "error_type": error_type,
        "failed_phase": failed_phase,
        "file_sha256": file_hashes,
        "hash_name": hash_name,
        "nargo_package_name": circuit_package.nargo_package_name,
        "nargo_version": _command_version(["nargo", "--version"]),
        "oracle_hash": oracle_hash,
        "package_dir": relative_or_str(circuit_package.package_dir, repo_root),
        "poseidon2_command_template": poseidon2_command_template,
        "python_version": sys.version.split()[0],
        "run_id": run_identity.run_id,
        "run_id_content_hash": run_identity.content_hash,
        "run_id_content_hash_inputs": run_identity.content_hash_inputs,
        "scheme": _backend_scheme(backend),
        "source_proof_path": relative_or_str(payload_path, repo_root),
        "source_proof_sha256": _source_proof_sha256(payload),
        "statement": statement_name,
        "status": status,
        "timings": timings,
        "witness_name": witness_name,
    }
    if backend_result is not None:
        metadata["artifact_paths"].update(
            {
                "proof": relative_or_str(backend_result.proof_path, repo_root),
                "public_inputs": (
                    relative_or_str(backend_result.public_inputs_path, repo_root)
                    if backend_result.public_inputs_path is not None
                    else None
                ),
                "vk": relative_or_str(backend_result.vk_path, repo_root),
            }
        )
        metadata["file_sha256"].update(
            {
                key: value
                for key, value in {
                    "proof": _hash_if_exists(backend_result.proof_path),
                    "public_inputs": _hash_if_exists(backend_result.public_inputs_path),
                    "vk": _hash_if_exists(backend_result.vk_path),
                }.items()
                if value is not None
            }
        )
        vk_hash_path = backend_result.vk_path.parent / "vk_hash"
        if vk_hash_path.exists():
            metadata["artifact_paths"]["vk_hash"] = relative_or_str(vk_hash_path, repo_root)
            metadata["file_sha256"]["vk_hash"] = sha256_file(vk_hash_path)
    write_json(path, metadata)


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

        if hash_name == "poseidon2":
            for statement_name in (
                statement
                for statement in config.statements
                if statement != "account_inclusion"
            ):
                for backend_name in config.backends:
                    for payload in payloads:
                        output_rows.append(
                            _template_row(
                                dataset_id=_dataset_id([payload]),
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                status="proxy",
                                error="proxy_poseidon2_statement_not_in_circuit",
                            )
                        )
            if "account_inclusion" not in config.statements:
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

        try:
            baselines = [verify_account_payload(payload, hash_variant) for payload in payloads]
        except Exception as exc:
            for statement_name in config.statements:
                if hash_name == "poseidon2" and statement_name != "account_inclusion":
                    continue
                for backend_name in config.backends:
                    for payload in payloads:
                        output_rows.append(
                            _template_row(
                                dataset_id=_dataset_id([payload]),
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                status="error",
                                error=f"Baseline verification failed for hash variant '{hash_name}': {exc}",
                            )
                        )
            continue

        for statement_name in config.statements:
            if statement_name != "account_inclusion":
                if hash_name == "poseidon2":
                    continue
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
                    run_dir_created = False
                    backend_result = None
                    compile_result = None
                    execute_result = None
                    circuit_json_path: Path | None = None
                    witness_gz_path: Path | None = None
                    timings: dict[str, int | float] = {}
                    current_phase = "prepare_inputs"
                    witness_name: str | None = None
                    run_identity = None
                    circuit_package = None
                    backend = None
                    package_prover_toml: Path | None = None
                    run_prover_toml: Path | None = None
                    source_circuit_json: Path | None = None
                    source_witness_gz: Path | None = None
                    run_dir: Path | None = None
                    timings_path: Path | None = None
                    try:
                        current_phase = "prepare_inputs"
                        prepared = statement.prepare(sample_payloads, sample_baselines)
                        noir_inputs = to_noir_input_map(prepared)
                        circuit_package = resolve_circuit_package(
                            statement_name,
                            hash_name,
                        )
                        backend = _build_backend(
                            backend_name,
                            bb_binary=config.bb_binary,
                            oracle_hash=config.bb_oracle_hash,
                        )
                        package_prover_toml = circuit_package.package_dir / "Prover.toml"
                        prover_toml_text = render_prover_toml(noir_inputs)
                        prover_sha = sha256_bytes(prover_toml_text.encode("utf-8"))
                        source_proof_sha = _source_proof_sha256(payload)
                        run_identity = build_run_identity(
                            dataset_id=sample_id,
                            statement=statement_name,
                            hash_name=hash_name,
                            backend_name=backend_name,
                            scheme=_backend_scheme(backend),
                            oracle_hash=config.bb_oracle_hash,
                            source_proof_path=_stable_source_proof_id(
                                payload,
                                Path.cwd(),
                            ),
                            source_proof_sha256=source_proof_sha,
                            nargo_package_name=circuit_package.nargo_package_name,
                            circuit_package_path=relative_or_str(
                                circuit_package.package_dir,
                                Path.cwd(),
                            ),
                            prover_toml_sha256=prover_sha,
                            circuit_package_identifier=circuit_package.nargo_package_name,
                        )
                        run_dir = build_run_dir(
                            config.artifact_root,
                            statement=statement_name,
                            hash_name=hash_name,
                            backend_name=backend_name,
                            run_id=run_identity.run_id,
                        )
                        current_phase = "create_run_dir"
                        create_run_dir(run_dir)
                        run_dir_created = True
                        run_prover_toml = run_dir / "Prover.toml"
                        witness_name = safe_filename(f"{hash_name}_{run_identity.run_id}_witness")
                        source_circuit_json = circuit_package.expected_circuit_json
                        source_witness_gz = (
                            circuit_package.package_dir.parent
                            / "target"
                            / f"{witness_name}.gz"
                        )
                        current_phase = "write_prover_toml"
                        run_prover_toml.write_text(prover_toml_text, encoding="utf-8")
                        package_prover_toml.write_text(prover_toml_text, encoding="utf-8")
                        if run_prover_toml.read_bytes() != package_prover_toml.read_bytes():
                            raise RuntimeError("Package and run Prover.toml contents diverged.")

                        current_phase = "compile"
                        compile_result = compile_isolated(
                            circuit_package,
                            run_dir=run_dir,
                        )
                        timings["compile_time_s"] = compile_result.elapsed_s
                        circuit_json_path = run_dir / "circuit.json"

                        current_phase = "execute_witness"
                        execute_result = execute_witness_isolated(
                            circuit_package,
                            witness_name=witness_name,
                            run_dir=run_dir,
                        )
                        timings["witness_generation_time_s"] = execute_result.elapsed_s
                        witness_gz_path = run_dir / "witness.gz"

                        current_phase = "prove"
                        backend_result = backend.prove_and_verify(
                            circuit_json=circuit_json_path,
                            witness_gz=witness_gz_path,
                            output_dir=run_dir,
                        )
                        timings["proof_generation_time_s"] = backend_result.prove_elapsed_s
                        timings["proof_verification_time_s"] = backend_result.verify_elapsed_s
                        timings["prove_peak_memory_bytes"] = backend_result.prove_peak_memory_bytes
                        timings["verify_peak_memory_bytes"] = backend_result.verify_peak_memory_bytes
                        current_phase = "verify"
                        timings_path = run_dir / "timings.json"
                        write_json(timings_path, timings)
                        _write_run_metadata(
                            path=run_dir / "metadata.json",
                            repo_root=Path.cwd(),
                            status="verified",
                            error=None,
                            failed_phase=None,
                            error_type=None,
                            error_message=None,
                            statement_name=statement_name,
                            hash_name=hash_name,
                            dataset_id=sample_id,
                            payload=payload,
                            circuit_package=circuit_package,
                            backend=backend,
                            oracle_hash=config.bb_oracle_hash,
                            run_identity=run_identity,
                            package_prover_toml=package_prover_toml,
                            run_prover_toml=run_prover_toml,
                            witness_name=witness_name,
                            circuit_json=circuit_json_path,
                            witness_gz=witness_gz_path,
                            source_circuit_json=source_circuit_json,
                            source_witness_gz=source_witness_gz,
                            vk_path=backend_result.vk_path,
                            proof_path=backend_result.proof_path,
                            public_inputs_path=backend_result.public_inputs_path,
                            backend_result=backend_result,
                            timings_path=timings_path,
                            timings=timings,
                            poseidon2_command_template=(
                                os.environ.get("THESIS_C_POSEIDON2_CMD")
                                if hash_name == "poseidon2"
                                else None
                            ),
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
                                witness_generation_time_s=execute_result.elapsed_s,
                                compile_time_s=compile_result.elapsed_s,
                                proof_size_bytes=backend_result.proof_size_bytes,
                                prove_peak_memory_bytes=backend_result.prove_peak_memory_bytes,
                                verify_peak_memory_bytes=backend_result.verify_peak_memory_bytes,
                                circuit_size_bytes=circuit_json_path.stat().st_size
                                if circuit_json_path is not None
                                else None,
                                constraint_count=_extract_constraint_count(
                                    circuit_json_path
                                )
                                if circuit_json_path is not None
                                else None,
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
                        error_message = str(exc)
                        error_type = type(exc).__name__
                        lowered = error_message.lower()
                        if "verification failed" in lowered:
                            failed_phase = "verify"
                        elif "proving failed" in lowered:
                            failed_phase = "prove"
                        else:
                            failed_phase = current_phase
                        if run_dir_created and run_dir is not None:
                            timings_path = run_dir / "timings.json"
                            write_json(timings_path, timings)
                            if (
                                circuit_package is not None
                                and backend is not None
                                and run_identity is not None
                                and package_prover_toml is not None
                                and run_prover_toml is not None
                            ):
                                vk_path = run_dir / "vk" / "vk"
                                proof_path = run_dir / "proof" / "proof"
                                public_inputs_path = run_dir / "public_inputs"
                                _write_run_metadata(
                                    path=run_dir / "metadata.json",
                                    repo_root=Path.cwd(),
                                    status="failed",
                                    error=error_message,
                                    failed_phase=failed_phase,
                                    error_type=error_type,
                                    error_message=error_message,
                                    statement_name=statement_name,
                                    hash_name=hash_name,
                                    dataset_id=sample_id,
                                    payload=payload,
                                    circuit_package=circuit_package,
                                    backend=backend,
                                    oracle_hash=config.bb_oracle_hash,
                                    run_identity=run_identity,
                                    package_prover_toml=package_prover_toml,
                                    run_prover_toml=run_prover_toml,
                                    witness_name=witness_name,
                                    circuit_json=circuit_json_path,
                                    witness_gz=witness_gz_path,
                                    source_circuit_json=source_circuit_json,
                                    source_witness_gz=source_witness_gz,
                                    vk_path=vk_path,
                                    proof_path=proof_path,
                                    public_inputs_path=public_inputs_path,
                                    backend_result=backend_result,
                                    timings_path=timings_path,
                                    timings=timings,
                                    poseidon2_command_template=(
                                        os.environ.get("THESIS_C_POSEIDON2_CMD")
                                        if hash_name == "poseidon2"
                                        else None
                                    ),
                                )
                        output_rows.append(
                            _error_record(
                                dataset_id=sample_id,
                                statement=statement_name,
                                hash_name=hash_name,
                                backend=backend_name,
                                payload=payload,
                                baseline=baseline,
                                error=error_message,
                            )
                        )
    return output_rows
