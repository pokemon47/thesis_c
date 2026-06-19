from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .base import HashVariant


def _normalize_hex(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    return text


@dataclass(slots=True)
class Poseidon2Config:
    command_template: str | None = None
    test_vectors: dict[str, str] | None = None


class Poseidon2Hash(HashVariant):
    name = "poseidon2"

    def __init__(self, config: Poseidon2Config | None = None):
        self.config = config or Poseidon2Config()
        self.test_vectors = {
            _normalize_hex(k): _normalize_hex(v)
            for k, v in (self.config.test_vectors or {}).items()
        }

    @classmethod
    def from_environment(cls) -> "Poseidon2Hash":
        command_template = os.getenv("THESIS_C_POSEIDON2_CMD")
        vectors_file = os.getenv("THESIS_C_POSEIDON2_VECTORS")
        vectors: dict[str, str] | None = None
        if vectors_file:
            path = Path(vectors_file)
            if path.exists():
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    vectors = {
                        str(k): str(v)
                        for k, v in loaded.items()
                        if isinstance(k, str) and isinstance(v, str)
                    }
        return cls(Poseidon2Config(command_template=command_template, test_vectors=vectors))

    def digest(self, data: bytes) -> bytes:
        input_hex = data.hex()
        mapped = self.test_vectors.get(input_hex)
        if mapped is not None:
            return bytes.fromhex(mapped)

        if self.config.command_template:
            return self._digest_with_command(input_hex)

        raise RuntimeError(
            "Poseidon2 digest adapter is not configured. "
            "Set THESIS_C_POSEIDON2_CMD or THESIS_C_POSEIDON2_VECTORS."
        )

    def _digest_with_command(self, input_hex: str) -> bytes:
        template = self.config.command_template or ""
        command = template.format(hex=input_hex, hex0x=f"0x{input_hex}")
        args = shlex.split(command)
        completed = subprocess.run(
            args,
            check=True,
            capture_output=True,
            text=True,
        )
        output = completed.stdout.strip() or completed.stderr.strip()
        normalized = _normalize_hex(output.splitlines()[-1])
        if not normalized:
            raise RuntimeError("Poseidon2 command produced empty output.")
        return bytes.fromhex(normalized)
