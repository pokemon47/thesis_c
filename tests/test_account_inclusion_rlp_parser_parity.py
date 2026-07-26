from __future__ import annotations

from pathlib import Path


def test_account_inclusion_rlp_parser_modules_are_byte_identical() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    keccak_parser = repo_root / "circuits" / "src" / "types" / "rlp_account.nr"
    poseidon2_parser = (
        repo_root / "circuits_poseidon2" / "src" / "types" / "rlp_account.nr"
    )

    assert keccak_parser.read_bytes() == poseidon2_parser.read_bytes()
