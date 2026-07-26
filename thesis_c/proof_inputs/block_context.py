from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

import rlp

from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.proof_inputs.normalizer import hex_to_bytes


HeaderRlpSource = Literal["source_exported", "reconstructed", "absent"]


@dataclass(frozen=True, slots=True)
class HeaderValidation:
    header_hash_matches: bool | None = None
    state_root_matches: bool | None = None
    header_ready: bool = False
    error: str | None = None


@dataclass(frozen=True, slots=True)
class GenerationProvenance:
    besu_version: str | None = None
    besu_commit: str | None = None
    thesis_commit: str | None = None
    poseidon2_parameter_identifier: str | None = None
    besu_flags: list[str] = field(default_factory=list)
    rpc_requests: list[Any] = field(default_factory=list)
    export_requests: list[Any] = field(default_factory=list)
    generation_command: str | None = None
    source_sha256: str | None = None
    generated_at: str | None = None


@dataclass(frozen=True, slots=True)
class BlockContext:
    network: str | None = None
    chain_id: int | None = None
    block_number: int | None = None
    block_hash: str | None = None
    parent_hash: str | None = None
    state_root: str | None = None
    raw_header_rlp: str | None = None
    header_rlp_len: int | None = None
    header_field_count: int | None = None
    fork: str | None = None
    header_hash_function: str = "keccak256"
    trie_hash_function: str | None = None
    header_rlp_source: HeaderRlpSource = "absent"
    reconstructed_header_fields: list[str] = field(default_factory=list)
    reconstructed_header_schema: str | None = None
    validation: HeaderValidation = field(default_factory=HeaderValidation)
    provenance: GenerationProvenance = field(default_factory=GenerationProvenance)


def parse_block_context(raw: dict[str, Any] | None) -> BlockContext:
    if not raw:
        return BlockContext()

    header_rlp = _first_present(raw, "rawHeaderRlp", "raw_header_rlp", "headerRlp", "header_rlp")
    reconstructed_fields = list(
        _first_present(raw, "reconstructedHeaderFields", "ordered_header_fields") or []
    )
    header_source: HeaderRlpSource
    if header_rlp:
        header_source = "source_exported"
    elif reconstructed_fields:
        header_source = "reconstructed"
    else:
        header_source = "absent"

    validation = validate_header_context(
        raw_header_rlp=header_rlp,
        block_hash=_first_present(raw, "blockHash", "block_hash", "hash"),
        state_root=_first_present(raw, "stateRoot", "state_root"),
    )

    return BlockContext(
        network=_first_present(raw, "network"),
        chain_id=_parse_optional_int(_first_present(raw, "chainId", "chain_id")),
        block_number=_parse_optional_int(_first_present(raw, "blockNumber", "block_number", "number")),
        block_hash=_first_present(raw, "blockHash", "block_hash", "hash"),
        parent_hash=_first_present(raw, "parentHash", "parent_hash"),
        state_root=_first_present(raw, "stateRoot", "state_root"),
        raw_header_rlp=header_rlp,
        header_rlp_len=len(hex_to_bytes(header_rlp)) if header_rlp else None,
        header_field_count=_header_field_count(header_rlp),
        fork=_first_present(raw, "fork"),
        header_hash_function=_first_present(raw, "headerHashFunction", "header_hash_function")
        or "keccak256",
        trie_hash_function=_first_present(raw, "trieHashFunction", "trie_hash_function"),
        header_rlp_source=header_source,
        reconstructed_header_fields=[str(item) for item in reconstructed_fields],
        reconstructed_header_schema=_first_present(
            raw,
            "reconstructedHeaderSchema",
            "forkSchema",
            "fork_schema",
        ),
        validation=validation,
        provenance=_parse_provenance(raw.get("provenance") or raw),
    )


def validate_header_context(
    *,
    raw_header_rlp: str | None,
    block_hash: str | None,
    state_root: str | None,
) -> HeaderValidation:
    if not raw_header_rlp:
        return HeaderValidation()
    try:
        header_bytes = hex_to_bytes(raw_header_rlp)
        decoded = rlp.decode(header_bytes)
        if not isinstance(decoded, list) or len(decoded) <= 3:
            return HeaderValidation(error="header_rlp_not_a_supported_list")

        header_hash = "0x" + Keccak256Hash().digest(header_bytes).hex()
        header_hash_matches = (
            block_hash is not None and header_hash.lower() == block_hash.lower()
        )
        decoded_state_root = decoded[3]
        if not isinstance(decoded_state_root, (bytes, bytearray)):
            return HeaderValidation(
                header_hash_matches=header_hash_matches,
                error="header_state_root_field_not_bytes",
            )
        decoded_state_root_hex = "0x" + bytes(decoded_state_root).hex()
        state_root_matches = (
            state_root is not None and decoded_state_root_hex.lower() == state_root.lower()
        )
        return HeaderValidation(
            header_hash_matches=header_hash_matches,
            state_root_matches=state_root_matches,
            header_ready=bool(header_hash_matches and state_root_matches),
        )
    except Exception as exc:  # pragma: no cover - exact RLP errors are dependency-specific.
        return HeaderValidation(error=str(exc))


def _parse_provenance(raw: dict[str, Any]) -> GenerationProvenance:
    return GenerationProvenance(
        besu_version=_first_present(raw, "besuVersion", "besu_version"),
        besu_commit=_first_present(raw, "besuCommit", "besu_commit"),
        thesis_commit=_first_present(raw, "thesisCommit", "thesis_commit"),
        poseidon2_parameter_identifier=_first_present(
            raw,
            "poseidon2ParameterIdentifier",
            "poseidon2_parameter_identifier",
        ),
        besu_flags=list(_first_present(raw, "besuFlags", "besu_flags") or []),
        rpc_requests=list(_first_present(raw, "rpcRequests", "rpc_requests") or []),
        export_requests=list(_first_present(raw, "exportRequests", "export_requests") or []),
        generation_command=_first_present(raw, "generationCommand", "generation_command"),
        source_sha256=_first_present(raw, "sourceSha256", "source_sha256"),
        generated_at=_first_present(raw, "generatedAt", "generated_at", "timestamp"),
    )


def _first_present(raw: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in raw and raw[name] is not None:
            return raw[name]
    return None


def _parse_optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value)
    return int(text[2:], 16) if text.lower().startswith("0x") else int(text)


def _header_field_count(raw_header_rlp: str | None) -> int | None:
    if not raw_header_rlp:
        return None
    try:
        decoded = rlp.decode(hex_to_bytes(raw_header_rlp))
    except Exception:
        return None
    return len(decoded) if isinstance(decoded, list) else None
