from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from thesis_c.noir.artifacts import (
    build_run_dir,
    build_run_identity,
    create_run_dir,
    resolve_circuit_package,
    safe_filename,
    sha256_file,
)


class ArtifactIsolationTests(unittest.TestCase):
    def test_resolves_keccak_account_inclusion_package(self) -> None:
        package = resolve_circuit_package(
            "account_inclusion",
            "keccak256",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits.json",
        )

    def test_resolves_poseidon2_account_inclusion_package(self) -> None:
        package = resolve_circuit_package(
            "account_inclusion",
            "poseidon2",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_poseidon2"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_poseidon2")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_poseidon2.json",
        )

    def test_resolves_keccak_balance_package(self) -> None:
        package = resolve_circuit_package(
            "balance_verification",
            "keccak256",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_balance"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_balance")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_balance.json",
        )

    def test_resolves_poseidon2_balance_package(self) -> None:
        package = resolve_circuit_package(
            "balance_verification",
            "poseidon2",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_balance_poseidon2"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_balance_poseidon2")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_balance_poseidon2.json",
        )

    def test_resolves_keccak_codehash_package(self) -> None:
        package = resolve_circuit_package(
            "codehash_verification",
            "keccak256",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_codehash"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_codehash")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_codehash.json",
        )

    def test_resolves_poseidon2_codehash_package(self) -> None:
        package = resolve_circuit_package(
            "codehash_verification",
            "poseidon2",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_codehash_poseidon2"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_codehash_poseidon2")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_codehash_poseidon2.json",
        )

    def test_resolves_keccak_eoa_activity_package(self) -> None:
        package = resolve_circuit_package(
            "eoa_activity",
            "keccak256",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_eoa_activity"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_eoa_activity")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_eoa_activity.json",
        )

    def test_resolves_poseidon2_eoa_activity_package(self) -> None:
        package = resolve_circuit_package(
            "eoa_activity",
            "poseidon2",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_eoa_activity_poseidon2"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_eoa_activity_poseidon2")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_eoa_activity_poseidon2.json",
        )

    def test_resolves_keccak_anchored_eoa_activity_package(self) -> None:
        package = resolve_circuit_package(
            "eoa_activity_anchored",
            "keccak256",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_eoa_activity_anchored"))
        self.assertEqual(package.nargo_package_name, "thesis_c_circuits_eoa_activity_anchored")
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_eoa_activity_anchored.json",
        )

    def test_resolves_poseidon2_anchored_eoa_activity_package(self) -> None:
        package = resolve_circuit_package(
            "eoa_activity_anchored_poseidon2",
            "poseidon2",
            repo_root=Path("."),
        )

        self.assertEqual(package.package_dir, Path("circuits_eoa_activity_anchored_poseidon2"))
        self.assertEqual(
            package.nargo_package_name,
            "thesis_c_circuits_eoa_activity_anchored_poseidon2",
        )
        self.assertEqual(
            package.expected_circuit_json,
            Path("target") / "thesis_c_circuits_eoa_activity_anchored_poseidon2.json",
        )

    def test_resolves_storage_slot_membership_packages(self) -> None:
        for hash_name, package_dir, package_name in (
            (
                "keccak256",
                "circuits_storage_slot_inclusion",
                "thesis_c_circuits_storage_slot_inclusion",
            ),
            (
                "poseidon2",
                "circuits_storage_slot_inclusion_poseidon2",
                "thesis_c_circuits_storage_slot_inclusion_poseidon2",
            ),
        ):
            package = resolve_circuit_package(
                "storage_slot_membership", hash_name, repo_root=Path(".")
            )
            self.assertEqual(package.package_dir, Path(package_dir))
            self.assertEqual(package.nargo_package_name, package_name)
            self.assertEqual(
                package.expected_circuit_json,
                Path("target") / f"{package_name}.json",
            )

    def test_run_id_is_deterministic_and_changes_with_hash(self) -> None:
        kwargs = {
            "dataset_id": "hoodi/block 9",
            "statement": "account_inclusion",
            "hash_name": "keccak256",
            "backend_name": "ultra_honk",
            "scheme": "ultra_honk",
            "oracle_hash": "keccak",
            "source_proof_path": "datasets/keccak/proof.json",
            "source_proof_sha256": "a" * 64,
            "nargo_package_name": "thesis_c_circuits",
            "circuit_package_path": "circuits",
            "prover_toml_sha256": "b" * 64,
            "circuit_package_identifier": "thesis_c_circuits",
        }

        left = build_run_identity(**kwargs)
        right = build_run_identity(**kwargs)
        changed = build_run_identity(
            **{
                **kwargs,
                "hash_name": "poseidon2",
                "nargo_package_name": "thesis_c_circuits_poseidon2",
                "circuit_package_identifier": "thesis_c_circuits_poseidon2",
            }
        )

        self.assertEqual(left.run_id, right.run_id)
        self.assertNotEqual(left.run_id, changed.run_id)
        self.assertNotIn("/", left.run_id)
        self.assertNotIn(" ", left.run_id)
        self.assertNotIn("created_timestamp", left.content_hash_inputs)

    def test_build_run_dir_separates_hashes(self) -> None:
        keccak = build_run_dir(
            "artifacts",
            statement="account_inclusion",
            hash_name="keccak256",
            backend_name="ultra_honk",
            run_id="sample",
        )
        poseidon = build_run_dir(
            "artifacts",
            statement="account_inclusion",
            hash_name="poseidon2",
            backend_name="ultra_honk",
            run_id="sample",
        )

        self.assertNotEqual(keccak, poseidon)
        self.assertEqual(
            keccak,
            Path("artifacts")
            / "account_inclusion"
            / "keccak256"
            / "ultra_honk"
            / "sample",
        )

    def test_existing_run_dir_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir) / "run"
            create_run_dir(run_dir)

            with self.assertRaises(FileExistsError):
                create_run_dir(run_dir)

    def test_safe_filename_and_sha256_helper(self) -> None:
        self.assertEqual(safe_filename("hoodi/block 9!"), "hoodi_block_9")

        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "payload.txt"
            path.write_text("one", encoding="utf-8")
            first = sha256_file(path)
            path.write_text("two", encoding="utf-8")
            second = sha256_file(path)

        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
