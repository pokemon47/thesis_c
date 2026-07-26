from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from shutil import copy2

from thesis_c.noir.artifacts import CircuitPackage


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    elapsed_s: float
    stdout: str
    stderr: str


def _run(command: list[str], cwd: Path) -> CommandResult:
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=True,
    )
    elapsed = time.perf_counter() - started
    return CommandResult(
        command=command,
        elapsed_s=elapsed,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _repo_root_for(program_dir: Path) -> Path:
    return program_dir.parent if program_dir.name in {"circuits", "circuits_poseidon2"} else Path.cwd()


def _validate_simple_name(kind: str, value: str) -> None:
    if not value or value in {".", ".."}:
        raise ValueError(f"Invalid {kind}: {value!r}")
    if Path(value).name != value:
        raise ValueError(f"Invalid {kind}: {value!r}")
    if "/" in value or "\\" in value:
        raise ValueError(f"Invalid {kind}: {value!r}")


def _expected_circuit_json_path(repo_root: Path, circuit_package: CircuitPackage) -> Path:
    _validate_simple_name("package name", circuit_package.nargo_package_name)
    expected = repo_root / "target" / f"{circuit_package.nargo_package_name}.json"
    if circuit_package.expected_circuit_json != expected:
        raise ValueError(
            "Circuit package artifact path does not match the package target directory."
        )
    return expected


def _expected_witness_path(repo_root: Path, witness_name: str) -> Path:
    _validate_simple_name("witness name", witness_name)
    return repo_root / "target" / f"{witness_name}.gz"


def compile_isolated(
    circuit_package: CircuitPackage,
    *,
    run_dir: Path,
) -> CommandResult:
    program_dir = circuit_package.package_dir
    repo_root = _repo_root_for(program_dir)
    expected_circuit_json = _expected_circuit_json_path(repo_root, circuit_package)
    # Remove any prior build output so we only copy a fresh circuit artifact.
    expected_circuit_json.unlink(missing_ok=True)

    compile_result = _run(
        ["nargo", "compile", "--program-dir", str(program_dir)],
        cwd=repo_root,
    )
    if not expected_circuit_json.exists():
        raise FileNotFoundError(f"Expected circuit JSON at {expected_circuit_json}")
    run_circuit_json = run_dir / "circuit.json"
    copy2(expected_circuit_json, run_circuit_json)

    return compile_result


def execute_witness_isolated(
    circuit_package: CircuitPackage,
    *,
    witness_name: str,
    run_dir: Path,
) -> CommandResult:
    program_dir = circuit_package.package_dir
    repo_root = _repo_root_for(program_dir)
    expected_witness = _expected_witness_path(repo_root, witness_name)
    # Remove any prior witness so a stale file cannot masquerade as a fresh run.
    expected_witness.unlink(missing_ok=True)

    execute_result = _run(
        ["nargo", "execute", witness_name, "--program-dir", str(program_dir)],
        cwd=repo_root,
    )
    if not expected_witness.exists():
        raise FileNotFoundError(f"Expected witness artifact at {expected_witness}")
    run_witness = run_dir / "witness.gz"
    copy2(expected_witness, run_witness)

    return execute_result
