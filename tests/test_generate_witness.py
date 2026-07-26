from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
import tomllib

from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.cli import build_parser, generate_witness_command
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.proof_inputs.normalizer import compute_leaf_value_commitment
from thesis_c.statements.account_inclusion import AccountInclusionStatement


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _thesis_c_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _sample_keccak_proof_path() -> Path:
    return _repo_root() / "sample_proofs" / "proof_keccak_slice.json"


def _sample_poseidon2_proof_path() -> Path:
    return _thesis_c_root() / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json"


def _sample_storage_keccak_proof_path() -> Path:
    return (
        _thesis_c_root()
        / "datasets/storage_slot_inclusion/keccak/controlled_contract_slot0_value42_depth3.json"
    )


class GenerateWitnessCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser()

    def test_generate_witness_command_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "nested" / "circuits" / "Prover.toml"
            args = self.parser.parse_args(
                [
                    "generate-witness",
                    "--input",
                    str(_sample_keccak_proof_path()),
                    "--hash",
                    "keccak256",
                    "--output",
                    str(output_path),
                ]
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = args.func(args)

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())

            output = stdout.getvalue()
            self.assertIn("Loaded payloads:", output)
            self.assertIn("Selected hash: keccak256", output)
            self.assertIn("Selected hash variant ID: 1", output)
            self.assertIn("Witness generation succeeded", output)

            generated = tomllib.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(generated["witness_version"], 1)
            self.assertEqual(generated["public_hash_variant_id"], 1)
            self.assertNotEqual(
                generated["public_account_address"], [0] * 20
            )
            self.assertIn("private_trie_key", generated)
            self.assertIn("private_active_node_count", generated)
            self.assertIn("private_node_bytes", generated)
            self.assertIn("private_node_lengths", generated)
            self.assertIn("private_node_kinds", generated)
            self.assertIn("private_node_list_layouts", generated)
            self.assertIn("private_node_item_layouts", generated)
            self.assertIn("private_node_compact_layouts", generated)
            self.assertIn("private_selected_ref_layouts", generated)
            self.assertIn("private_selected_ref_bytes", generated)
            self.assertIn("private_selected_ref_lengths", generated)
            self.assertIn("private_selected_ref_kinds", generated)
            self.assertIn("private_terminal_value", generated)
            self.assertIn("private_terminal_value_len", generated)

            payloads = load_proof_path(_sample_keccak_proof_path())
            hash_variant = Keccak256Hash()
            baseline_results = [verify_account_payload(payload, hash_variant) for payload in payloads]
            prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
            expected_inputs = to_noir_input_map(prepared)
            self.assertEqual(
                generated["private_trie_key"],
                expected_inputs["private_trie_key"],
            )
            self.assertEqual(
                int(generated["public_leaf_value_commitment"]),
                expected_inputs["public_leaf_value_commitment"],
            )
            self.assertNotIn("private_node_rlp_bytes", generated)
            self.assertIn("private_leaf_outer_list_layout", generated)

    def test_generate_witness_command_invalid_proof_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "bad-proof.json"
            output_path = Path(tmp_dir) / "Prover.toml"

            bad_payload = json.loads(_sample_keccak_proof_path().read_text(encoding="utf-8"))
            assert isinstance(bad_payload, dict)
            result = bad_payload.get("result")
            assert isinstance(result, dict)
            result["accountProof"] = ["0x00"]
            input_path.write_text(json.dumps(bad_payload), encoding="utf-8")

            args = self.parser.parse_args(
                [
                    "generate-witness",
                    "--input",
                    str(input_path),
                    "--hash",
                    "keccak256",
                    "--output",
                    str(output_path),
                ]
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = args.func(args)

            self.assertEqual(exit_code, 1)
            self.assertFalse(output_path.exists())
            self.assertIn("Baseline verification failed for payload 0", stdout.getvalue())

    def test_generate_storage_witness_uses_storage_statement_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "storage" / "Prover.toml"
            args = self.parser.parse_args(
                [
                    "generate-witness",
                    "--input",
                    str(_sample_storage_keccak_proof_path()),
                    "--hash",
                    "keccak256",
                    "--statement",
                    "storage_slot_membership",
                    "--output",
                    str(output_path),
                ]
            )

            with redirect_stdout(io.StringIO()):
                exit_code = args.func(args)

            self.assertEqual(exit_code, 0)
            generated = tomllib.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(generated["public_hash_variant_id"], 1)
            self.assertEqual(generated["public_expected_storage_value"], [0] * 31 + [42])
            self.assertIn("private_storage_node_rlp_bytes", generated)
            self.assertNotIn("public_storage_root", generated)

    def test_generate_poseidon2_witness_uses_parser_layout_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "nested" / "circuits_poseidon2" / "Prover.toml"
            command_path = (
                "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/"
                "build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}"
            )
            with patch.dict(os.environ, {"THESIS_C_POSEIDON2_CMD": command_path}, clear=False):
                args = self.parser.parse_args(
                    [
                        "generate-witness",
                        "--input",
                        str(_sample_poseidon2_proof_path()),
                        "--hash",
                        "poseidon2",
                        "--output",
                        str(output_path),
                    ]
                )

                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = args.func(args)

            self.assertEqual(exit_code, 0)
            self.assertTrue(output_path.exists())

            generated = tomllib.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(generated["witness_version"], 1)
            self.assertEqual(
                list(generated)[:5],
                [
                    "witness_version",
                    "public_state_root",
                    "public_state_root_field",
                    "public_account_address",
                    "public_hash_variant_id",
                ],
            )
            self.assertEqual(generated["public_hash_variant_id"], 2)
            self.assertIn("public_state_root_field", generated)
            self.assertNotIn("public_leaf_value_commitment", generated)
            self.assertEqual(len(generated["public_state_root"]), 32)
            self.assertEqual(len(generated["public_account_address"]), 20)
            self.assertEqual(len(generated["private_trie_key"]), 32)
            self.assertEqual(generated["private_active_node_count"], 4)
            self.assertEqual(len(generated["private_node_bytes"]), 16)
            self.assertEqual(len(generated["private_node_lengths"]), 16)
            self.assertEqual(len(generated["private_node_kinds"]), 16)
            self.assertEqual(len(generated["private_node_list_layouts"]), 16)
            self.assertEqual(len(generated["private_node_item_layouts"]), 16)
            self.assertEqual(len(generated["private_node_compact_layouts"]), 16)
            self.assertEqual(len(generated["private_selected_ref_layouts"]), 16)
            self.assertEqual(len(generated["private_selected_ref_bytes"]), 16)
            self.assertEqual(len(generated["private_selected_ref_lengths"]), 16)
            self.assertEqual(len(generated["private_selected_ref_kinds"]), 16)
            self.assertEqual(len(generated["private_terminal_value"]), 256)
            self.assertNotIn("private_branch_child_hash_fields", generated)
            self.assertNotIn("private_branch_children_fields", generated)
            self.assertNotIn("private_address_hash", generated)
            self.assertIn("Witness generation succeeded", stdout.getvalue())

    def test_generate_witness_command_unsupported_hash_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "proof.json"
            output_path = Path(tmp_dir) / "Prover.toml"
            input_path.write_text(
                _sample_keccak_proof_path().read_text(encoding="utf-8"),
                encoding="utf-8",
            )

            args = self.parser.parse_args(
                [
                    "generate-witness",
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ]
            )
            args.hash = "blake2"

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = generate_witness_command(args)

            self.assertEqual(exit_code, 2)
            self.assertFalse(output_path.exists())
            self.assertIn("Unsupported hash", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
