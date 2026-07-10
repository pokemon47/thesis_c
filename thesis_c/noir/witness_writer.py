from __future__ import annotations

from pathlib import Path
from typing import Any


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _to_toml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if value > 9223372036854775807 or value < -9223372036854775808:
            return f'"{value}"'
        return str(value)
    if isinstance(value, str):
        return f'"{_toml_escape(value)}"'
    if isinstance(value, list):
        return "[" + ", ".join(_to_toml(item) for item in value) + "]"
    if isinstance(value, tuple):
        return "[" + ", ".join(_to_toml(item) for item in value) + "]"
    if isinstance(value, dict):
        # Inline tables are sufficient for simple benchmark metadata fields.
        entries = [f"{k}={_to_toml(v)}" for k, v in value.items()]
        return "{ " + ", ".join(entries) + " }"
    return f'"{_toml_escape(str(value))}"'


def render_prover_toml(values: dict[str, Any]) -> str:
    lines = [f"{key} = {_to_toml(value)}" for key, value in values.items()]
    return "\n".join(lines) + "\n"


def write_prover_toml(path: str | Path, values: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_prover_toml(values), encoding="utf-8")
