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


def compile_isolated(
    circuit_package: CircuitPackage,
    *,
    run_dir: Path,
) -> CommandResult:
    program_dir = circuit_package.package_dir
    repo_root = _repo_root_for(program_dir)

    compile_result = _run(
        ["nargo", "compile", "--program-dir", str(program_dir)],
        cwd=repo_root,
    )
    if not circuit_package.expected_circuit_json.exists():
        raise FileNotFoundError(
            f"Expected circuit JSON at {circuit_package.expected_circuit_json}"
        )
    run_circuit_json = run_dir / "circuit.json"
    copy2(circuit_package.expected_circuit_json, run_circuit_json)

    return compile_result


def execute_witness_isolated(
    circuit_package: CircuitPackage,
    *,
    witness_name: str,
    run_dir: Path,
) -> CommandResult:
    program_dir = circuit_package.package_dir
    repo_root = _repo_root_for(program_dir)

    execute_result = _run(
        ["nargo", "execute", witness_name, "--program-dir", str(program_dir)],
        cwd=repo_root,
    )
    expected_witness = repo_root / "target" / f"{witness_name}.gz"
    if not expected_witness.exists():
        raise FileNotFoundError(f"Expected witness artifact at {expected_witness}")
    run_witness = run_dir / "witness.gz"
    copy2(expected_witness, run_witness)

    return execute_result
