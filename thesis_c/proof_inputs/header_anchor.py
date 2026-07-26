from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import rlp

from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.proof_inputs.block_context import HeaderValidation, validate_header_context
from thesis_c.proof_inputs.normalizer import hex_to_bytes, hex_to_u8_list, pad_u8_list


HEADER_WITNESS_VERSION = 1
MAX_HEADER_BYTES = 640
EXPECTED_HEADER_FIELD_COUNT = 20

_DEFAULT_FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "datasets" / "header_anchor" / "fixtures.json"
)


@dataclass(frozen=True, slots=True)
class HeaderAnchorFixture:
    fixture_id: str
    network: str
    chain_id: int
    block_number: int
    block_hash: str
    state_root: str
    raw_header_rlp: str
    header_rlp_len: int
    header_field_count: int
    header_rlp_source: str
    header_hash_function: str
    source_reference: str
    reconstructed_header_fields: list[str]


@dataclass(frozen=True, slots=True)
class HeaderUniformityReport:
    fixture_count: int
    field_count: int
    min_header_len: int
    max_header_len: int
    layout_signature: tuple[str, ...]
    header_rlp_sources: tuple[str, ...]


def load_header_anchor_fixtures(path: str | Path | None = None) -> list[HeaderAnchorFixture]:
    fixture_path = Path(path) if path is not None else _DEFAULT_FIXTURE_PATH
    raw = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixtures: list[HeaderAnchorFixture] = []
    for entry in raw:
        fixture = HeaderAnchorFixture(
            fixture_id=str(entry["fixture_id"]),
            network=str(entry["network"]),
            chain_id=int(entry["chain_id"]),
            block_number=int(entry["block_number"]),
            block_hash=str(entry["block_hash"]),
            state_root=str(entry["state_root"]),
            raw_header_rlp=str(entry["raw_header_rlp"]),
            header_rlp_len=int(entry["header_rlp_len"]),
            header_field_count=int(entry["header_field_count"]),
            header_rlp_source=str(entry["header_rlp_source"]),
            header_hash_function=str(entry["header_hash_function"]),
            source_reference=str(entry["source_reference"]),
            reconstructed_header_fields=[str(item) for item in entry["reconstructed_header_fields"]],
        )
        _validate_fixture_shape(fixture)
        fixtures.append(fixture)
    if not fixtures:
        raise ValueError(f"No header fixtures found in {fixture_path}")
    return fixtures


def load_default_header_anchor_fixtures() -> list[HeaderAnchorFixture]:
    return load_header_anchor_fixtures(_DEFAULT_FIXTURE_PATH)


def validate_header_fixture(fixture: HeaderAnchorFixture) -> HeaderValidation:
    return validate_header_context(
        raw_header_rlp=fixture.raw_header_rlp,
        block_hash=fixture.block_hash,
        state_root=fixture.state_root,
    )


def header_uniformity_report(fixtures: list[HeaderAnchorFixture]) -> HeaderUniformityReport:
    if not fixtures:
        raise ValueError("At least one header fixture is required.")

    field_counts = {fixture.header_field_count for fixture in fixtures}
    if field_counts != {EXPECTED_HEADER_FIELD_COUNT}:
        raise ValueError(
            f"Expected a uniform {EXPECTED_HEADER_FIELD_COUNT}-field header layout, got {sorted(field_counts)}."
        )

    layout_signature = tuple(fixtures[0].reconstructed_header_fields)
    for fixture in fixtures[1:]:
        if tuple(fixture.reconstructed_header_fields) != layout_signature:
            raise ValueError("Selected header fixtures do not share a uniform field layout.")

    lengths = [fixture.header_rlp_len for fixture in fixtures]
    return HeaderUniformityReport(
        fixture_count=len(fixtures),
        field_count=EXPECTED_HEADER_FIELD_COUNT,
        min_header_len=min(lengths),
        max_header_len=max(lengths),
        layout_signature=layout_signature,
        header_rlp_sources=tuple(fixture.header_rlp_source for fixture in fixtures),
    )


def build_header_anchor_witness(fixture: HeaderAnchorFixture) -> dict[str, Any]:
    validation = validate_header_fixture(fixture)
    if validation.error is not None or not validation.header_ready:
        raise ValueError(
            f"Header fixture {fixture.fixture_id} failed validation: "
            f"hash_matches={validation.header_hash_matches}, "
            f"state_root_matches={validation.state_root_matches}, error={validation.error}"
        )

    header_bytes = hex_to_bytes(fixture.raw_header_rlp)
    if len(header_bytes) != fixture.header_rlp_len:
        raise ValueError(
            f"Header fixture {fixture.fixture_id} declares length {fixture.header_rlp_len} "
            f"but raw bytes are {len(header_bytes)}."
        )
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise ValueError(
            f"Header fixture {fixture.fixture_id} exceeds MAX_HEADER_BYTES={MAX_HEADER_BYTES}."
        )

    return {
        "witness_version": HEADER_WITNESS_VERSION,
        "public_block_hash": hex_to_u8_list(fixture.block_hash),
        "public_expected_state_root": hex_to_u8_list(fixture.state_root),
        "private_header_bytes": pad_u8_list(hex_to_u8_list(fixture.raw_header_rlp), MAX_HEADER_BYTES),
        "private_header_len": fixture.header_rlp_len,
    }


def write_header_anchor_prover_toml(path: str | Path, fixture: HeaderAnchorFixture) -> None:
    from thesis_c.noir.witness_writer import write_prover_toml

    write_prover_toml(path, build_header_anchor_witness(fixture))


def synthesize_header_anchor_fixture(
    template: HeaderAnchorFixture,
    *,
    state_root: str,
    fixture_id: str | None = None,
    block_hash: str | None = None,
    block_number: int | None = None,
    source_reference: str | None = None,
) -> HeaderAnchorFixture:
    template_header = hex_to_bytes(template.raw_header_rlp)
    decoded = rlp.decode(template_header)
    if not isinstance(decoded, list) or len(decoded) <= 3:
        raise ValueError("Header template is not a supported canonical list.")

    decoded[3] = hex_to_bytes(state_root)
    raw_header_bytes = rlp.encode(decoded)
    synthetic_block_hash = block_hash or "0x" + Keccak256Hash().digest(raw_header_bytes).hex()
    synthetic_fixture = HeaderAnchorFixture(
        fixture_id=fixture_id or f"{template.fixture_id}_synthetic",
        network=template.network,
        chain_id=template.chain_id,
        block_number=template.block_number if block_number is None else block_number,
        block_hash=synthetic_block_hash,
        state_root=state_root,
        raw_header_rlp="0x" + raw_header_bytes.hex(),
        header_rlp_len=len(raw_header_bytes),
        header_field_count=template.header_field_count,
        header_rlp_source="synthetic",
        header_hash_function=template.header_hash_function,
        source_reference=source_reference or template.source_reference,
        reconstructed_header_fields=list(template.reconstructed_header_fields),
    )
    validation = validate_header_fixture(synthetic_fixture)
    if validation.error is not None or not validation.header_ready:
        raise ValueError(
            f"Synthetic header fixture {synthetic_fixture.fixture_id} failed validation: "
            f"hash_matches={validation.header_hash_matches}, "
            f"state_root_matches={validation.state_root_matches}, error={validation.error}"
        )
    return synthetic_fixture


def _validate_fixture_shape(fixture: HeaderAnchorFixture) -> None:
    if fixture.header_rlp_len != len(hex_to_bytes(fixture.raw_header_rlp)):
        raise ValueError(
            f"Fixture {fixture.fixture_id} length mismatch: "
            f"declared {fixture.header_rlp_len} vs raw bytes {len(hex_to_bytes(fixture.raw_header_rlp))}."
        )
    if fixture.header_field_count != EXPECTED_HEADER_FIELD_COUNT:
        raise ValueError(
            f"Fixture {fixture.fixture_id} must expose {EXPECTED_HEADER_FIELD_COUNT} header fields."
        )
    if fixture.header_rlp_len <= 0:
        raise ValueError(f"Fixture {fixture.fixture_id} must have a non-zero header length.")
    if fixture.header_rlp_len > MAX_HEADER_BYTES:
        raise ValueError(
            f"Fixture {fixture.fixture_id} exceeds MAX_HEADER_BYTES={MAX_HEADER_BYTES}."
        )
