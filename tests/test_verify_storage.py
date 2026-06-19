from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import rlp

from thesis_c.baseline.verifier_adapter import (
    verify_account_payload,
    verify_storage_entry,
    verify_storage_payload,
)
from thesis_c.cli import build_parser
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.proof_inputs.schema import ProofPayload, StorageProofEntry


def _bytes_to_nibbles(data: bytes) -> list[int]:
    out: list[int] = []
    for byte in data:
        out.append(byte >> 4)
        out.append(byte & 0x0F)
    return out


def _encode_compact(path_nibbles: list[int], is_leaf: bool) -> bytes:
    if any(nibble < 0 or nibble > 15 for nibble in path_nibbles):
        raise ValueError("Invalid nibble in path.")

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


def _build_payload(
    *,
    slot_key: int = 1,
    slot_value: int = 5,
    storage_hash_override: str | None = None,
    entry_value_override: str | None = None,
) -> tuple[ProofPayload, str, StorageProofEntry]:
    hash_variant = Keccak256Hash()
    slot_key_bytes = slot_key.to_bytes(32, "big")

    storage_path = _bytes_to_nibbles(hash_variant.digest(slot_key_bytes))
    storage_leaf_value = rlp.encode(_int_to_minimal_bytes(slot_value))
    storage_leaf_node = rlp.encode([_encode_compact(storage_path, True), storage_leaf_value])
    storage_root = hash_variant.digest(storage_leaf_node)
    storage_root_hex = "0x" + storage_root.hex()

    storage_entry = StorageProofEntry(
        key=hex(slot_key),
        value=entry_value_override if entry_value_override is not None else hex(slot_value),
        proof=["0x" + storage_leaf_node.hex()],
    )

    address_bytes = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
    account_path = _bytes_to_nibbles(hash_variant.digest(address_bytes))
    code_hash = bytes.fromhex("11" * 32)
    account_leaf_value = rlp.encode([b"", b"", storage_root, code_hash])
    account_leaf_node = rlp.encode([_encode_compact(account_path, True), account_leaf_value])

    payload = ProofPayload(
        address="0x" + address_bytes.hex(),
        balance="0x0",
        code_hash="0x" + code_hash.hex(),
        nonce="0x0",
        storage_hash=storage_hash_override if storage_hash_override else storage_root_hex,
        account_proof=["0x" + account_leaf_node.hex()],
        storage_proof=[storage_entry],
    )
    return payload, storage_root_hex, storage_entry


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


class StorageVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.hash_variant = Keccak256Hash()

    def test_verify_account_payload_still_succeeds(self) -> None:
        payload, expected_storage_root, _ = _build_payload()

        result = verify_account_payload(payload, self.hash_variant)

        self.assertTrue(result.ok)
        self.assertIsNotNone(result.leaf)
        assert result.leaf is not None
        self.assertEqual(result.leaf.storage_root, expected_storage_root)

    def test_verify_storage_entry_success(self) -> None:
        _, storage_root, entry = _build_payload(slot_key=1, slot_value=5)

        result = verify_storage_entry(entry, storage_root, self.hash_variant)

        self.assertTrue(result.ok)
        self.assertEqual(result.expected_value, "0x5")
        self.assertEqual(result.decoded_value, "0x5")
        self.assertEqual(result.decoded_value_int, 5)
        self.assertIsNone(result.error)

    def test_verify_storage_entry_zero_value(self) -> None:
        _, storage_root, entry = _build_payload(slot_key=2, slot_value=0)

        result = verify_storage_entry(entry, storage_root, self.hash_variant)

        self.assertTrue(result.ok)
        self.assertEqual(result.expected_value, "0x0")
        self.assertEqual(result.decoded_value, "0x0")
        self.assertEqual(result.decoded_value_int, 0)

    def test_verify_storage_entry_value_mismatch_fails(self) -> None:
        _, storage_root, entry = _build_payload(slot_key=3, slot_value=7, entry_value_override="0x8")

        result = verify_storage_entry(entry, storage_root, self.hash_variant)

        self.assertFalse(result.ok)
        self.assertIn("Storage value mismatch", result.error or "")

    def test_verify_storage_entry_corrupted_node_fails(self) -> None:
        _, storage_root, entry = _build_payload(slot_key=4, slot_value=9)
        node_bytes = bytes.fromhex(entry.proof[0][2:])
        mutated = bytes([node_bytes[0] ^ 0x01, *node_bytes[1:]])
        bad_entry = StorageProofEntry(
            key=entry.key,
            value=entry.value,
            proof=["0x" + mutated.hex()],
        )

        result = verify_storage_entry(bad_entry, storage_root, self.hash_variant)

        self.assertFalse(result.ok)
        self.assertTrue(
            "Node hash mismatch" in (result.error or "")
            or "Path nibble mismatch" in (result.error or "")
            or "Unsupported node shape" in (result.error or "")
        )

    def test_verify_storage_payload_storage_root_mismatch_fails(self) -> None:
        payload, _, _ = _build_payload(storage_hash_override="0x" + ("22" * 32))

        result = verify_storage_payload(payload, self.hash_variant)

        self.assertFalse(result.ok)
        self.assertFalse(result.storage_root_matches_payload)
        self.assertIn("Storage root mismatch", result.error or "")


class VerifyStorageCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = build_parser()

    def test_verify_storage_command_success(self) -> None:
        payload, _, _ = _build_payload(slot_key=11, slot_value=15)
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "proof.json"
            output_path = Path(tmp_dir) / "report.json"
            input_path.write_text(json.dumps(_to_rpc_payload(payload)), encoding="utf-8")

            args = self.parser.parse_args(
                [
                    "verify-storage",
                    "--input",
                    str(input_path),
                    "--hash",
                    "keccak256",
                    "--output-json",
                    str(output_path),
                ]
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = args.func(args)

            self.assertEqual(exit_code, 0)
            self.assertIn("Storage entries ok: 1/1", stdout.getvalue())
            self.assertTrue(output_path.exists())
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(len(report), 1)
            self.assertTrue(report[0]["ok"])

    def test_verify_storage_command_failure_exit_code(self) -> None:
        payload, _, _ = _build_payload(slot_key=13, slot_value=21, entry_value_override="0x99")
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "bad-proof.json"
            input_path.write_text(json.dumps(_to_rpc_payload(payload)), encoding="utf-8")

            args = self.parser.parse_args(
                ["verify-storage", "--input", str(input_path), "--hash", "keccak256"]
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = args.func(args)

            self.assertEqual(exit_code, 1)
            self.assertIn("Payloads ok: 0/1", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
