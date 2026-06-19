from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class CommandResult:
    command: list[str]
    elapsed_s: float
    stdout: str
    stderr: str


@dataclass(slots=True)
class NoirExecutionArtifacts:
    circuit_json: Path
    witness_gz: Path
    compile_result: CommandResult
    execute_result: CommandResult


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


def _latest_file(paths: list[Path]) -> Path:
    if not paths:
        raise FileNotFoundError("Expected generated Noir artifact, none found.")
    return max(paths, key=lambda p: p.stat().st_mtime)


def compile_and_execute(
    circuits_dir: str | Path,
    execute_name: str = "witness",
) -> NoirExecutionArtifacts:
    program_dir = Path(circuits_dir)
    compile_result = _run(
        ["nargo", "compile", "--program-dir", str(program_dir)],
        cwd=program_dir,
    )
    execute_result = _run(
        ["nargo", "execute", execute_name, "--program-dir", str(program_dir)],
        cwd=program_dir,
    )

    target_dir = program_dir / "target"
    circuit_json = _latest_file(
        [p for p in target_dir.glob("*.json") if not p.name.endswith(".debug.json")]
    )
    witness_gz = _latest_file(list(target_dir.glob("*.gz")))

    return NoirExecutionArtifacts(
        circuit_json=circuit_json,
        witness_gz=witness_gz,
        compile_result=compile_result,
        execute_result=execute_result,
    )
