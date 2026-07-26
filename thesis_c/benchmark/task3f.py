from __future__ import annotations

from typing import Any


UNAVAILABLE_ROW_SCHEMA = "task3f-unavailable-v1"


def build_unavailable_row(
    *,
    statement: str,
    hash_name: str,
    proving_system: str,
    tool_versions: dict[str, str],
    fixture_path: str,
    fixture_sha256: str,
    failed_phase: str,
    error: str,
    circuit_compiled: bool,
    witness_generated: bool,
) -> dict[str, Any]:
    """Build a non-measurement record for a toolchain-unavailable row."""
    return {
        "schema": UNAVAILABLE_ROW_SCHEMA,
        "status": "unavailable",
        "failed_phase": failed_phase,
        "statement": statement,
        "hash_name": hash_name,
        "backend": proving_system,
        "scheme": proving_system,
        "tool_versions": dict(tool_versions),
        "unsupported_scheme": proving_system,
        "error": error,
        "fixture_path": fixture_path,
        "fixture_sha256": fixture_sha256,
        "circuit_compiled": circuit_compiled,
        "witness_generated": witness_generated,
        "proof_size_bytes": 0,
        "verification_ok": False,
        "fallback_used": False,
    }
