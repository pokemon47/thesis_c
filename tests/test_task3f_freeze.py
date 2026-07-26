from __future__ import annotations

from pathlib import Path

from thesis_c.benchmark.task3f import UNAVAILABLE_ROW_SCHEMA, build_unavailable_row
from thesis_c.noir.artifacts import resolve_circuit_package


ROOT = Path(__file__).resolve().parents[1]


FAMILIES = {
    "account_inclusion": (
        ("keccak256", "circuits", "thesis_c_circuits", 54),
        ("poseidon2", "circuits_poseidon2", "thesis_c_circuits_poseidon2", 54),
    ),
    "balance_verification": (
        ("keccak256", "circuits_balance", "thesis_c_circuits_balance", 57),
        (
            "poseidon2",
            "circuits_balance_poseidon2",
            "thesis_c_circuits_balance_poseidon2",
            58,
        ),
    ),
    "codehash_verification": (
        ("keccak256", "circuits_codehash", "thesis_c_circuits_codehash", 85),
        (
            "poseidon2",
            "circuits_codehash_poseidon2",
            "thesis_c_circuits_codehash_poseidon2",
            86,
        ),
    ),
    "eoa_activity": (
        ("keccak256", "circuits_eoa_activity", "thesis_c_circuits_eoa_activity", 85),
        (
            "poseidon2",
            "circuits_eoa_activity_poseidon2",
            "thesis_c_circuits_eoa_activity_poseidon2",
            87,
        ),
    ),
    "eoa_activity_anchored": (
        (
            "keccak256",
            "circuits_eoa_activity_anchored",
            "thesis_c_circuits_eoa_activity_anchored",
            85,
        ),
    ),
    "eoa_activity_anchored_poseidon2": (
        (
            "poseidon2",
            "circuits_eoa_activity_anchored_poseidon2",
            "thesis_c_circuits_eoa_activity_anchored_poseidon2",
            87,
        ),
    ),
    "storage_slot_membership": (
        (
            "keccak256",
            "circuits_storage_slot_inclusion",
            "thesis_c_circuits_storage_slot_inclusion",
            117,
        ),
        (
            "poseidon2",
            "circuits_storage_slot_inclusion_poseidon2",
            "thesis_c_circuits_storage_slot_inclusion_poseidon2",
            118,
        ),
    ),
}


def test_all_frozen_routes_and_package_names() -> None:
    for statement, variants in FAMILIES.items():
        for hash_name, package_dir, package_name, _public_count in variants:
            resolved = resolve_circuit_package(statement, hash_name, ROOT)
            assert resolved.package_dir == ROOT / package_dir
            assert resolved.nargo_package_name == package_name
            assert resolved.expected_circuit_json == ROOT / "target" / f"{package_name}.json"
            assert (resolved.package_dir / "Nargo.toml").exists()


def test_frozen_public_counts_are_explicit_and_distinct() -> None:
    counts = [item[3] for variants in FAMILIES.values() for item in variants]
    assert counts == [54, 54, 57, 58, 85, 86, 85, 87, 85, 87, 117, 118]


def test_unavailable_row_is_non_measurement_and_no_fallback() -> None:
    row = build_unavailable_row(
        statement="storage_slot_membership",
        hash_name="keccak256",
        proving_system="ultra_plonk",
        tool_versions={"nargo": "1.0.0-beta.22", "bb": "5.0.0-nightly.20260522"},
        fixture_path="datasets/storage_slot_inclusion/keccak/example.json",
        fixture_sha256="a" * 64,
        failed_phase="prove",
        error="ultra_plonk not in {chonk,avm,ultra_honk}",
        circuit_compiled=True,
        witness_generated=True,
    )
    assert row["schema"] == UNAVAILABLE_ROW_SCHEMA
    assert row["status"] == "unavailable"
    assert row["proof_size_bytes"] == 0
    assert row["verification_ok"] is False
    assert row["fallback_used"] is False
    assert row["unsupported_scheme"] == "ultra_plonk"
