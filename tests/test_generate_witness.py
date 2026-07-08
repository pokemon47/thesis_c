from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
import tomllib

from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.cli import build_parser, generate_witness_command
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.statements.account_inclusion import AccountInclusionStatement


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _sample_keccak_proof_path() -> Path:
    return _repo_root() / "sample_proofs" / "proof_keccak_slice.json"


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
            self.assertEqual(generated["public_hash_variant_id"], 1)
            self.assertNotEqual(
                generated["public_account_address"], [0] * 20
            )

            payloads = load_proof_path(_sample_keccak_proof_path())
            hash_variant = Keccak256Hash()
            baseline_results = [verify_account_payload(payload, hash_variant) for payload in payloads]
            prepared = AccountInclusionStatement().prepare(payloads, baseline_results)
            expected_inputs = to_noir_input_map(prepared)
            self.assertEqual(
                generated["private_path_nibbles"],
                expected_inputs["private_path_nibbles"],
            )

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
