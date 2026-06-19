from __future__ import annotations

import json
from pathlib import Path


def load_test_vectors(path: str | Path) -> dict[str, str]:
    vector_path = Path(path)
    if not vector_path.exists():
        return {}
    loaded = json.loads(vector_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"Expected map in vector file: {vector_path}")
    return {str(k): str(v) for k, v in loaded.items()}


def save_test_vectors(path: str | Path, vectors: dict[str, str]) -> None:
    vector_path = Path(path)
    vector_path.parent.mkdir(parents=True, exist_ok=True)
    vector_path.write_text(json.dumps(vectors, indent=2, sort_keys=True), encoding="utf-8")
