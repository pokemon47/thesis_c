from __future__ import annotations

from dataclasses import asdict
from typing import Any

from thesis_c.proof_inputs.header_anchor import (
    HeaderAnchorFixture,
    build_header_anchor_witness,
    load_default_header_anchor_fixtures,
    synthesize_header_anchor_fixture,
)


def header_anchor_fixture_for_state_root(
    state_root: str,
    *,
    block_number: int | None = None,
    fixture_id_suffix: str = "state",
    source_reference: str | None = None,
    allow_synthetic: bool = False,
) -> tuple[HeaderAnchorFixture, str]:
    fixtures = load_default_header_anchor_fixtures()
    for fixture in fixtures:
        if fixture.state_root.lower() == state_root.lower():
            return fixture, "real"

    if not allow_synthetic:
        raise LookupError(
            "No real header anchor fixture matches state root "
            f"{state_root}. Synthetic headers are test-only and require allow_synthetic=True."
        )

    template = fixtures[0]
    synthetic = synthesize_header_anchor_fixture(
        template,
        state_root=state_root,
        fixture_id=f"{template.fixture_id}_{fixture_id_suffix}_synthetic",
        block_number=template.block_number if block_number is None else block_number,
        source_reference=source_reference
        or f"synthetic header synthesized from {template.source_reference}",
    )
    return synthetic, "synthetic"


def build_anchored_header_inputs(
    *,
    state_root: str,
    block_number: int | None,
    fixture_id_suffix: str,
    source_reference: str | None,
    allow_synthetic: bool = False,
) -> dict[str, Any]:
    fixture, fixture_classification = header_anchor_fixture_for_state_root(
        state_root,
        block_number=block_number,
        fixture_id_suffix=fixture_id_suffix,
        source_reference=source_reference,
        allow_synthetic=allow_synthetic,
    )
    witness = build_header_anchor_witness(fixture)
    return {
        "header_anchor": asdict(fixture),
        "header_fixture_classification": fixture_classification,
        "header_witness_version": witness["witness_version"],
        "private_header_bytes": witness["private_header_bytes"],
        "private_header_len": witness["private_header_len"],
        "public_block_hash": witness["public_block_hash"],
        "public_expected_state_root": witness["public_expected_state_root"],
    }
