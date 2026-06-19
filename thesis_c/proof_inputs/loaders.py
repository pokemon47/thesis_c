from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .schema import ProofPayload, StorageProofEntry


def _unwrap_result_object(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("Expected object payload.")
    if "result" in raw and isinstance(raw["result"], dict):
        return raw["result"]
    if "accountProof" in raw:
        return raw
    raise ValueError("Object is not a valid eth_getProof payload.")


def _coerce_storage_proof(items: Any) -> list[StorageProofEntry]:
    if not isinstance(items, list):
        return []
    out: list[StorageProofEntry] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        proof = item.get("proof", [])
        out.append(
            StorageProofEntry(
                key=str(item.get("key", "0x")),
                value=str(item.get("value", "0x0")),
                proof=[str(x) for x in proof] if isinstance(proof, list) else [],
            )
        )
    return out


def _extract_block_number(container: dict[str, Any]) -> int | None:
    # Accept common metadata locations used in local datasets.
    candidates = [
        container.get("blockNumber"),
        container.get("block_number"),
        container.get("meta", {}).get("blockNumber")
        if isinstance(container.get("meta"), dict)
        else None,
    ]
    for value in candidates:
        if value is None:
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("0x"):
                return int(text, 16)
            if text.isdigit():
                return int(text)
    return None


def _to_payload(
    wrapped_object: dict[str, Any], source_file: str, source_index: int
) -> ProofPayload:
    result = _unwrap_result_object(wrapped_object)
    return ProofPayload(
        address=str(result.get("address", "0x")),
        balance=str(result.get("balance", "0x0")),
        code_hash=str(result.get("codeHash", "0x")),
        nonce=str(result.get("nonce", "0x0")),
        storage_hash=str(result.get("storageHash", "0x")),
        account_proof=[str(x) for x in result.get("accountProof", [])],
        storage_proof=_coerce_storage_proof(result.get("storageProof", [])),
        block_number=_extract_block_number(wrapped_object),
        state_root=(
            str(result.get("stateRoot"))
            if result.get("stateRoot") is not None
            else None
        ),
        source_file=source_file,
        source_index=source_index,
        raw_result=result,
    )


def load_proof_file(path: str | Path) -> list[ProofPayload]:
    file_path = Path(path)
    raw = json.loads(file_path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [
            _to_payload(item, str(file_path), idx)
            for idx, item in enumerate(raw)
            if isinstance(item, dict)
        ]
    if isinstance(raw, dict):
        return [_to_payload(raw, str(file_path), 0)]
    raise ValueError(f"Unsupported JSON root in {file_path}")


def load_proof_path(path: str | Path) -> list[ProofPayload]:
    target = Path(path)
    if target.is_file():
        return load_proof_file(target)
    if not target.is_dir():
        raise FileNotFoundError(f"Path does not exist: {target}")

    payloads: list[ProofPayload] = []
    for file_path in sorted(target.rglob("*.json")):
        payloads.extend(load_proof_file(file_path))
    return payloads
