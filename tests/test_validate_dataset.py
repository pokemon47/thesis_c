from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import rlp

from thesis_c.cli import build_parser
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.proof_inputs.schema import ProofPayload, StorageProofEntry
from thesis_c.validation.runner import DatasetValidationConfig, run_dataset_validation
from thesis_c.validation.storage import EMPTY_STORAGE_ROOT


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def _sample_keccak_proof() -> dict[str, object]:
    sample_path = _repo_root() / "sample_proofs" / "proof_keccak_slice.json"
    return _read_json(sample_path)


def _besu_non_empty_storage_fixture() -> dict[str, object]:
    fixture_path = (
        _repo_root()
        / "besu_bonsai"
        / "ethereum"
        / "api"
        / "src"
        / "test"
        / "resources"
        / "org"
        / "hyperledger"
        / "besu"
        / "ethereum"
        / "api"
        / "jsonrpc"
        / "eth"
        / "eth_getProof_latest.json"
    )
    loaded = _read_json(fixture_path)
    assert isinstance(loaded, dict)
    response = loaded.get("response")
    assert isinstance(response, dict)
    return response


def _bytes_to_nibbles(data: bytes) -> list[int]:
    out: list[int] = []
    for byte in data:
        out.append(byte >> 4)
        out.append(byte & 0x0F)
    return out


def _encode_compact(path_nibbles: list[int], is_leaf: bool) -> bytes:
    flag = 2 if is_leaf else 0
    if len(path_nibbles) % 2 == 1:
        prefixed = [flag + 1, *path_nibbles]
    else:
        prefixed = [flag, 0, *path_nibbles]
    out = bytearray()
    for idx in range(0, len(prefixed), 2):
        out.append((prefixed[idx] << 4) | prefixed[idx + 1])
    return bytes(out)


def _int_to_minimal_bytes(value: int) -> bytes:
    if value < 0:
        raise ValueError("Negative integers are not supported.")
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _to_rpc_payload(payload: ProofPayload) -> dict[str, object]:
    return {
        "result": {
            "address": payload.address,
            "balance": payload.balance,
            "codeHash": payload.code_hash,
            "nonce": payload.nonce,
            "storageHash": payload.storage_hash,
            "accountProof": payload.account_proof,
            "storageProof": [
                {"key": entry.key, "value": entry.value, "proof": entry.proof}
                for entry in payload.storage_proof
            ],
        }
    }


def _build_non_empty_storage_payload() -> ProofPayload:
    hash_variant = Keccak256Hash()
    slot_key = 1
    slot_value = 5
    slot_key_bytes = slot_key.to_bytes(32, "big")

    storage_path = _bytes_to_nibbles(hash_variant.digest(slot_key_bytes))
    storage_leaf_value = rlp.encode(_int_to_minimal_bytes(slot_value))
    storage_leaf_node = rlp.encode([_encode_compact(storage_path, True), storage_leaf_value])
    storage_root = hash_variant.digest(storage_leaf_node)
    storage_entry = StorageProofEntry(
        key=hex(slot_key),
        value=hex(slot_value),
        proof=["0x" + storage_leaf_node.hex()],
    )

    address_bytes = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
    account_path = _bytes_to_nibbles(hash_variant.digest(address_bytes))
    code_hash = bytes.fromhex("11" * 32)
    account_leaf_value = rlp.encode([b"", b"", storage_root, code_hash])
    account_leaf_node = rlp.encode([_encode_compact(account_path, True), account_leaf_value])

    return ProofPayload(
        address="0x" + address_bytes.hex(),
        balance="0x0",
        code_hash="0x" + code_hash.hex(),
        nonce="0x0",
        storage_hash="0x" + storage_root.hex(),
        account_proof=["0x" + account_leaf_node.hex()],
        storage_proof=[storage_entry],
    )


def _write_json_file(tmp_dir: str, name: str, payload: object) -> Path:
    path = Path(tmp_dir) / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _collect_issue_codes(result) -> set[str]:
    return {issue.code for record in result.records for issue in record.issues}


class ValidateDatasetRunnerTests(unittest.TestCase):
    def test_valid_sample_loading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "sample.json", _sample_keccak_proof())
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        self.assertEqual(result.summary.files_scanned, 1)
        self.assertEqual(result.summary.records_total, 1)
        schema_codes = [
            issue.code
            for record in result.records
            for issue in record.issues
            if issue.check == "schema_validation"
        ]
        self.assertEqual(schema_codes, [])

    def test_invalid_schema_root_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "bad-schema.json", {"foo": "bar"})
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        self.assertEqual(result.summary.records_total, 1)
        self.assertIn("schema_invalid_root_object", _collect_issue_codes(result))

    def test_malformed_rlp_is_reported(self) -> None:
        bad_payload = _sample_keccak_proof()
        assert isinstance(bad_payload, dict)
        result_obj = bad_payload.get("result")
        assert isinstance(result_obj, dict)
        result_obj["accountProof"] = ["0x00"]
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "bad-rlp.json", bad_payload)
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        codes = _collect_issue_codes(result)
        self.assertTrue(
            "proof_node_not_list" in codes
            or "account_bounded_precheck_failed" in codes
            or "account_proof_verification_failed" in codes
        )

    def test_node_size_validation_failure(self) -> None:
        bad_payload = _sample_keccak_proof()
        assert isinstance(bad_payload, dict)
        result_obj = bad_payload.get("result")
        assert isinstance(result_obj, dict)
        account_proof = result_obj.get("accountProof")
        assert isinstance(account_proof, list)
        account_proof[0] = "0x" + ("11" * 545)
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "oversized.json", bad_payload)
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        self.assertIn("account_node_too_large", _collect_issue_codes(result))

    def test_account_leaf_mismatch_is_reported(self) -> None:
        mismatched = _sample_keccak_proof()
        assert isinstance(mismatched, dict)
        result_obj = mismatched.get("result")
        assert isinstance(result_obj, dict)
        result_obj["balance"] = "0x1234"
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "balance-mismatch.json", mismatched)
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        self.assertIn("account_balance_mismatch", _collect_issue_codes(result))

    def test_empty_storage_proof_requires_empty_root(self) -> None:
        payload = _build_non_empty_storage_payload()
        payload.storage_proof = [StorageProofEntry(key="0x1", value="0x0", proof=[])]
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "empty-proof-non-empty-root.json", _to_rpc_payload(payload))
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        self.assertIn("storage_empty_proof_requires_empty_root", _collect_issue_codes(result))

    def test_empty_storage_proof_zero_value_allowed_for_empty_root(self) -> None:
        sample = _sample_keccak_proof()
        assert isinstance(sample, dict)
        result_obj = sample.get("result")
        assert isinstance(result_obj, dict)
        result_obj["storageHash"] = EMPTY_STORAGE_ROOT
        result_obj["storageProof"] = [{"key": "0x1", "value": "0x0", "proof": []}]
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "empty-proof-empty-root.json", sample)
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        self.assertNotIn("storage_empty_proof_requires_empty_root", _collect_issue_codes(result))

    def test_non_empty_storage_fixture_from_besu(self) -> None:
        fixture = _besu_non_empty_storage_fixture()
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "besu-storage.json", fixture)
            result = run_dataset_validation(
                DatasetValidationConfig(input_path=input_path, hash_name="keccak256")
            )

        self.assertEqual(result.summary.records_total, 1)
        self.assertGreater(result.records[0].storage_proof_node_count, 0)
        schema_errors = [
            issue.code
            for issue in result.records[0].issues
            if issue.check == "schema_validation"
        ]
        self.assertEqual(schema_errors, [])


class ValidateDatasetCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser()

    def test_validate_dataset_command_writes_csv_and_json_reports(self) -> None:
        bad_payload = _sample_keccak_proof()
        assert isinstance(bad_payload, dict)
        result_obj = bad_payload.get("result")
        assert isinstance(result_obj, dict)
        result_obj["balance"] = "0x1234"

        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = _write_json_file(tmp_dir, "input.json", bad_payload)
            output_dir = Path(tmp_dir) / "reports"
            args = self.parser.parse_args(
                [
                    "validate-dataset",
                    "--input",
                    str(input_path),
                    "--hash",
                    "keccak256",
                    "--output-dir",
                    str(output_dir),
                ]
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = args.func(args)

            self.assertEqual(exit_code, 1)
            self.assertIn("CSV:", stdout.getvalue())
            self.assertIn("JSON:", stdout.getvalue())

            csv_path = output_dir / "validation.csv"
            json_path = output_dir / "validation.json"
            self.assertTrue(csv_path.exists())
            self.assertTrue(json_path.exists())

            report = _read_json(json_path)
            assert isinstance(report, dict)
            summary = report.get("summary")
            assert isinstance(summary, dict)
            self.assertGreater(summary.get("error_count", 0), 0)


if __name__ == "__main__":
    unittest.main()
