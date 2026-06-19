from __future__ import annotations

import csv
from pathlib import Path

from thesis_c.benchmark.metrics import BenchmarkRecord


def write_csv(path: str | Path, rows: list[BenchmarkRecord]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        output.write_text("", encoding="utf-8")
        return

    dictionaries = [row.to_dict() for row in rows]
    fieldnames = sorted({key for row in dictionaries for key in row.keys()})
    with output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in dictionaries:
            writer.writerow(row)
