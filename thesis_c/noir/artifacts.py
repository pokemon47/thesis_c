from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class CircuitPackage:
    statement: str
    hash_name: str
    package_dir: Path
    nargo_package_name: str
    expected_circuit_json: Path


@dataclass(frozen=True, slots=True)
class RunIdentity:
    run_id: str
    content_hash: str
    content_hash_inputs: dict[str, str]


SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_-]+")


def safe_filename(raw: str) -> str:
    safe = SAFE_NAME_RE.sub("_", raw).strip("_")
    return safe or "unnamed"


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def resolve_circuit_package(
    statement: str,
    hash_name: str,
    repo_root: str | Path = ".",
) -> CircuitPackage:
    root = Path(repo_root)
    routes = {
        ("account_inclusion", "keccak256"): (
            "circuits",
            "thesis_c_circuits",
        ),
        ("account_inclusion_anchored", "keccak256"): (
            "circuits_account_inclusion_anchored",
            "thesis_c_circuits_account_inclusion_anchored",
        ),
        ("account_inclusion_anchored_poseidon2", "poseidon2"): (
            "circuits_account_inclusion_anchored_poseidon2",
            "thesis_c_circuits_account_inclusion_anchored_poseidon2",
        ),
        ("account_inclusion", "poseidon2"): (
            "circuits_poseidon2",
            "thesis_c_circuits_poseidon2",
        ),
        ("balance_verification_anchored", "keccak256"): (
            "circuits_balance_anchored",
            "thesis_c_circuits_balance_anchored",
        ),
        ("balance_verification_anchored_poseidon2", "poseidon2"): (
            "circuits_balance_anchored_poseidon2",
            "thesis_c_circuits_balance_anchored_poseidon2",
        ),
        ("balance_verification", "keccak256"): (
            "circuits_balance",
            "thesis_c_circuits_balance",
        ),
        ("balance_verification", "poseidon2"): (
            "circuits_balance_poseidon2",
            "thesis_c_circuits_balance_poseidon2",
        ),
        ("codehash_verification_anchored", "keccak256"): (
            "circuits_codehash_anchored",
            "thesis_c_circuits_codehash_anchored",
        ),
        ("codehash_verification_anchored_poseidon2", "poseidon2"): (
            "circuits_codehash_anchored_poseidon2",
            "thesis_c_circuits_codehash_anchored_poseidon2",
        ),
        ("codehash_verification", "keccak256"): (
            "circuits_codehash",
            "thesis_c_circuits_codehash",
        ),
        ("codehash_verification", "poseidon2"): (
            "circuits_codehash_poseidon2",
            "thesis_c_circuits_codehash_poseidon2",
        ),
        ("eoa_activity", "keccak256"): (
            "circuits_eoa_activity",
            "thesis_c_circuits_eoa_activity",
        ),
        ("eoa_activity", "poseidon2"): (
            "circuits_eoa_activity_poseidon2",
            "thesis_c_circuits_eoa_activity_poseidon2",
        ),
        ("eoa_activity_anchored", "keccak256"): (
            "circuits_eoa_activity_anchored",
            "thesis_c_circuits_eoa_activity_anchored",
        ),
        ("eoa_activity_anchored_poseidon2", "poseidon2"): (
            "circuits_eoa_activity_anchored_poseidon2",
            "thesis_c_circuits_eoa_activity_anchored_poseidon2",
        ),
        ("storage_slot_membership", "keccak256"): (
            "circuits_storage_slot_inclusion",
            "thesis_c_circuits_storage_slot_inclusion",
        ),
        ("storage_slot_membership", "poseidon2"): (
            "circuits_storage_slot_inclusion_poseidon2",
            "thesis_c_circuits_storage_slot_inclusion_poseidon2",
        ),
    }
    try:
        package_dir, package_name = routes[(statement, hash_name)]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported circuit package for statement={statement!r}, hash={hash_name!r}"
        ) from exc

    return CircuitPackage(
        statement=statement,
        hash_name=hash_name,
        package_dir=root / package_dir,
        nargo_package_name=package_name,
        expected_circuit_json=root / "target" / f"{package_name}.json",
    )


def build_run_identity(
    *,
    dataset_id: str,
    statement: str,
    hash_name: str,
    backend_name: str,
    scheme: str,
    oracle_hash: str,
    source_proof_path: str,
    source_proof_sha256: str,
    nargo_package_name: str,
    circuit_package_path: str,
    prover_toml_sha256: str,
    circuit_package_identifier: str,
) -> RunIdentity:
    content_hash_inputs = {
        "backend_name": backend_name,
        "circuit_package_identifier": circuit_package_identifier,
        "circuit_package_path": circuit_package_path,
        "dataset_id": dataset_id,
        "hash_name": hash_name,
        "nargo_package_name": nargo_package_name,
        "oracle_hash": oracle_hash,
        "prover_toml_sha256": prover_toml_sha256,
        "scheme": scheme,
        "source_proof_path": source_proof_path,
        "source_proof_sha256": source_proof_sha256,
        "statement": statement,
    }
    encoded = json.dumps(
        content_hash_inputs,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    content_hash = sha256_bytes(encoded)
    run_id = "__".join(
        [
            safe_filename(dataset_id),
            safe_filename(hash_name),
            safe_filename(backend_name),
            content_hash[:12],
        ]
    )
    return RunIdentity(
        run_id=run_id,
        content_hash=content_hash,
        content_hash_inputs=content_hash_inputs,
    )


def build_run_dir(
    artifact_root: str | Path,
    *,
    statement: str,
    hash_name: str,
    backend_name: str,
    run_id: str,
) -> Path:
    return (
        Path(artifact_root)
        / safe_filename(statement)
        / safe_filename(hash_name)
        / safe_filename(backend_name)
        / safe_filename(run_id)
    )


def create_run_dir(run_dir: Path) -> None:
    if run_dir.exists():
        raise FileExistsError(f"Artifact run directory already exists: {run_dir}")
    (run_dir / "proof").mkdir(parents=True)


def relative_or_str(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
