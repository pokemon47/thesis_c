from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from shutil import copy2, rmtree

from thesis_c.backends.base import BackendRunResult, SnarkBackend
from thesis_c.benchmark.memory import run_command_with_memory


@dataclass(slots=True)
class BarretenbergConfig:
    scheme: str
    oracle_hash: str = "keccak"
    binary: str = "bb"


class BarretenbergBackend(SnarkBackend):
    def __init__(self, name: str, config: BarretenbergConfig):
        self.name = name
        self.config = config

    def _path_or_default(self, output_dir: Path, file_name: str) -> Path:
        return output_dir / file_name

    def prove_and_verify(
        self,
        circuit_json: Path,
        witness_gz: Path,
        output_dir: Path,
    ) -> BackendRunResult:
        circuit_json = Path(circuit_json).resolve()
        witness_gz = Path(witness_gz).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        proof_dir = output_dir / "proof"
        proof_dir.mkdir(parents=True, exist_ok=True)
        proof_path = proof_dir / "proof"
        vk_path = self._path_or_default(output_dir, "vk")
        vk_file = vk_path / "vk"
        public_inputs_path = self._path_or_default(output_dir, "public_inputs")
        prove_output_dir = output_dir / "bb_prove"
        prove_output_dir.mkdir(parents=True, exist_ok=True)

        write_vk = run_command_with_memory(
            [
                self.config.binary,
                "write_vk",
                "-s",
                self.config.scheme,
                "--oracle_hash",
                self.config.oracle_hash,
                "-b",
                str(circuit_json),
                "-o",
                str(vk_path),
            ],
            cwd=output_dir,
        )

        prove_cmd = [
            self.config.binary,
            "prove",
            "-s",
            self.config.scheme,
            "--oracle_hash",
            self.config.oracle_hash,
            "-b",
            str(circuit_json),
            "-w",
            str(witness_gz),
            "-o",
            str(prove_output_dir),
        ]
        if write_vk.return_code == 0 and vk_file.exists():
            prove_cmd.extend(["-k", str(vk_file)])
        else:
            # Fallback for bb versions where `write_vk` differs.
            prove_cmd.append("--write_vk")

        prove = run_command_with_memory(prove_cmd, cwd=output_dir)
        if prove.return_code != 0:
            raise RuntimeError(
                f"{self.name} proving failed.\nSTDOUT:\n{prove.stdout}\nSTDERR:\n{prove.stderr}"
            )

        staged_proof = prove_output_dir / "proof"
        staged_public_inputs = prove_output_dir / "public_inputs"
        if not staged_proof.exists():
            raise FileNotFoundError(f"Expected proof artifact at {staged_proof}")
        copy2(staged_proof, proof_path)
        if staged_public_inputs.exists():
            copy2(staged_public_inputs, public_inputs_path)
        rmtree(prove_output_dir)

        if not proof_path.exists():
            raise FileNotFoundError(f"Expected proof artifact at {proof_path}")
        if not vk_file.exists():
            raise FileNotFoundError(
                f"Expected verification key artifact at {vk_file}. "
                "Check Barretenberg CLI version/flags."
            )

        verify_cmd = [
            self.config.binary,
            "verify",
            "-s",
            self.config.scheme,
            "--oracle_hash",
            self.config.oracle_hash,
            "-p",
            str(proof_path),
            "-k",
            str(vk_file),
        ]
        if public_inputs_path.exists():
            verify_cmd.extend(["-i", str(public_inputs_path)])

        verify = run_command_with_memory(verify_cmd, cwd=output_dir)
        if verify.return_code != 0:
            raise RuntimeError(
                f"{self.name} verification failed.\nSTDOUT:\n{verify.stdout}\nSTDERR:\n{verify.stderr}"
            )

        return BackendRunResult(
            backend_name=self.name,
            prove_elapsed_s=prove.elapsed_s,
            verify_elapsed_s=verify.elapsed_s,
            prove_peak_memory_bytes=prove.peak_memory_bytes,
            verify_peak_memory_bytes=verify.peak_memory_bytes,
            proof_path=proof_path,
            vk_path=vk_file,
            public_inputs_path=public_inputs_path if public_inputs_path.exists() else None,
            proof_size_bytes=proof_path.stat().st_size,
            verification_ok=True,
            prove_stdout=prove.stdout,
            prove_stderr=prove.stderr,
            verify_stdout=verify.stdout,
            verify_stderr=verify.stderr,
        )
