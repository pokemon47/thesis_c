from __future__ import annotations

from pathlib import Path


def _foundation_source(name: str) -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / name / "src" / "variable_depth_account_verifier.nr").read_text()


def _backend_independent_prefix(source: str) -> str:
    # Hashing and Field bridges are intentionally backend-specific. The
    # complete shape, depth, padding, and terminal-result foundation is not.
    return source.split("pub fn assert_variable_depth_", 1)[0]


def test_variable_depth_backend_independent_foundation_has_structural_parity() -> None:
    packages = [
        "circuits",
        "circuits_poseidon2",
        "circuits_balance",
        "circuits_balance_poseidon2",
        "circuits_eoa_activity",
        "circuits_eoa_activity_poseidon2",
        "circuits_eoa_activity_anchored",
        "circuits_eoa_activity_anchored_poseidon2",
    ]
    full_sources = [_foundation_source(package) for package in packages]
    normalized = [_backend_independent_prefix(source) for source in full_sources]
    assert all(source == normalized[0] for source in normalized)
    for marker in (
        "terminal_index",
        "node_kinds",
        "path_nibbles",
        "account_value_payload_offset",
        "account_value_payload_len",
    ):
        assert marker in full_sources[0]


def test_codehash_variable_depth_packages_share_the_expanded_verifier_surface() -> None:
    root = Path(__file__).resolve().parents[1]
    keccak = (root / "circuits_codehash/src/variable_depth_account_verifier.nr").read_text()
    poseidon2 = (root / "circuits_codehash_poseidon2/src/variable_depth_account_verifier.nr").read_text()

    assert "AuthenticatedTerminalValue" in keccak
    assert "AuthenticatedTerminalValue" in poseidon2
    assert "assert_inclusion" in keccak
    assert "assert_inclusion" in poseidon2
    assert "node_item_layouts" in keccak
    assert "node_item_layouts" in poseidon2
    assert "selected_ref_layouts" in keccak
    assert "selected_ref_layouts" in poseidon2
    assert "expanded_hash_keccak" in keccak
    assert "expanded_hash_poseidon2" in poseidon2
    assert "private_state_root_field" in poseidon2


def test_variable_depth_parity_allows_only_documented_backend_sections() -> None:
    root = Path(__file__).resolve().parents[1]
    keccak = (root / "circuits/src/variable_depth_account_verifier.nr").read_text()
    poseidon2 = (root / "circuits_poseidon2/src/variable_depth_account_verifier.nr").read_text()
    assert "assert_variable_depth_keccak" in keccak
    assert "assert_variable_depth_poseidon2" in poseidon2
    assert "hash_keccak" in keccak
    assert "hash_poseidon2" in poseidon2


def test_all_mirrored_packages_expose_both_backend_boundaries() -> None:
    root = Path(__file__).resolve().parents[1]
    packages = [
        "circuits",
        "circuits_poseidon2",
        "circuits_balance",
        "circuits_balance_poseidon2",
        "circuits_eoa_activity",
        "circuits_eoa_activity_poseidon2",
        "circuits_eoa_activity_anchored",
        "circuits_eoa_activity_anchored_poseidon2",
    ]
    for package in packages:
        source = (root / package / "src/variable_depth_account_verifier.nr").read_text()
        assert "authenticated_terminal" in source
        assert "inactive" in source
        assert "assert_variable_depth_" in source


def test_codehash_packages_expose_the_expanded_boundary_surface() -> None:
    root = Path(__file__).resolve().parents[1]
    packages = [
        "circuits_codehash",
        "circuits_codehash_poseidon2",
    ]
    for package in packages:
        source = (root / package / "src/variable_depth_account_verifier.nr").read_text()
        assert "AuthenticatedTerminalValue" in source
        assert "assert_inclusion" in source
        assert "node_item_layouts" in source
        assert "selected_ref_layouts" in source
