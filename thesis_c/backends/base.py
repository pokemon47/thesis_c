from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class BackendRunResult:
    backend_name: str
    prove_elapsed_s: float
    verify_elapsed_s: float
    prove_peak_memory_bytes: int
    verify_peak_memory_bytes: int
    proof_path: Path
    vk_path: Path
    public_inputs_path: Path | None
    proof_size_bytes: int
    verification_ok: bool
    prove_stdout: str
    prove_stderr: str
    verify_stdout: str
    verify_stderr: str


class SnarkBackend(ABC):
    name: str

    @abstractmethod
    def prove_and_verify(
        self,
        circuit_json: Path,
        witness_gz: Path,
        output_dir: Path,
    ) -> BackendRunResult:
        raise NotImplementedError
