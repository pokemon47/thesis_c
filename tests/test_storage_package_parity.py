from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KECCAK = ROOT / "circuits_storage_slot_inclusion"
POSEIDON2 = ROOT / "circuits_storage_slot_inclusion_poseidon2"


def test_storage_account_parser_is_byte_identical() -> None:
    assert (
        (KECCAK / "src/types/rlp_account.nr").read_bytes()
        == (POSEIDON2 / "src/types/rlp_account.nr").read_bytes()
    )


def test_storage_leaf_backend_independent_invariants_are_mirrored() -> None:
    keccak = (KECCAK / "src/storage_leaf_verifier.nr").read_text()
    poseidon2 = (POSEIDON2 / "src/storage_leaf_verifier.nr").read_text()
    required = (
        "hash_node",
        "storage_root",
        "storage_key",
        "private_storage_path_nibbles",
        "assert_canonical_rlp_list_item",
        "assert_canonical_compact_path_item",
        "assert_canonical_account_scalar_item",
        "storage_value_item_layout",
        "storage_value_active_len",
        "storage_value_padded",
        "public_expected_storage_value",
        "active_len > 0",
        "active_len <= 32",
    )
    for marker in required:
        assert marker in keccak, marker
        assert marker in poseidon2, marker

    for forbidden in ("branch", "extension", "storage_proof_depth >"):
        assert forbidden not in keccak.lower()
        assert forbidden not in poseidon2.lower()

    # These are the only intentional backend differences in the leaf helper.
    assert "hash_poseidon2" in poseidon2
    assert "hash_keccak" in keccak
    assert "authenticated_storage_root_field" in poseidon2
