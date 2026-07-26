from __future__ import annotations

from pathlib import Path


def test_codehash_rlp_parser_sources_are_byte_for_byte_identical() -> None:
    thesis_c_root = Path(__file__).resolve().parents[1]
    keccak_parser = thesis_c_root / "circuits_codehash" / "src" / "rlp_balance.nr"
    poseidon2_parser = (
        thesis_c_root / "circuits_codehash_poseidon2" / "src" / "rlp_balance.nr"
    )

    assert keccak_parser.read_bytes() == poseidon2_parser.read_bytes()
