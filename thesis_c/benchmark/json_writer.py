from __future__ import annotations

import json
from pathlib import Path

from thesis_c.benchmark.metrics import BenchmarkRecord


def write_json(path: str | Path, rows: list[BenchmarkRecord]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = [row.to_dict() for row in rows]
    output.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
