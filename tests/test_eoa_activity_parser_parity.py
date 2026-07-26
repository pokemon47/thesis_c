from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_eoa_activity_rlp_parser_is_byte_identical_for_keccak_and_poseidon2() -> None:
    keccak = (ROOT / "circuits_eoa_activity" / "src" / "rlp_balance.nr").read_bytes()
    poseidon2 = (
        ROOT / "circuits_eoa_activity_poseidon2" / "src" / "rlp_balance.nr"
    ).read_bytes()
    anchored_keccak = (
        ROOT / "circuits_eoa_activity_anchored" / "src" / "rlp_balance.nr"
    ).read_bytes()
    anchored_poseidon2 = (
        ROOT / "circuits_eoa_activity_anchored_poseidon2" / "src" / "rlp_balance.nr"
    ).read_bytes()
    assert keccak == poseidon2
    assert keccak == anchored_keccak
    assert poseidon2 == anchored_poseidon2
