from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
import rlp

from thesis_c.baseline.storage_layout import (
    derive_storage_trie_key,
    parse_one_node_storage_leaf,
    storage_slot_bytes,
)
from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.proof_inputs.loaders import load_proof_file
from thesis_c.proof_inputs.normalizer import hex_to_bytes
from thesis_c.statements.storage_slot_membership import StorageSlotMembershipStatement


ROOT = Path(__file__).resolve().parents[1]
KECCAK_FIXTURE = ROOT / "datasets/storage_slot_inclusion/keccak/controlled_contract_slot0_value42_depth3.json"
POSEIDON_FIXTURE = ROOT / "datasets/storage_slot_inclusion/poseidon2/controlled_contract_slot0_value42_depth2.json"
POSEIDON_CMD = (
    "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/"
    "besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}"
)


def _prepared(path: Path, hash_variant, expected: str | None = None):
    payload = load_proof_file(path)[0]
    baseline = verify_account_payload(payload, hash_variant)
    assert baseline.ok
    return payload, baseline, StorageSlotMembershipStatement(expected).prepare(
        [payload], [baseline]
    )


def test_retained_keccak_storage_preparation_and_mapping() -> None:
    assert hashlib.sha256(KECCAK_FIXTURE.read_bytes()).hexdigest() == (
        "a393db4db92e9b72313d9553e52c9174ec2f2d2db4692b4e4a9951693f993864"
    )
    payload, baseline, prepared = _prepared(KECCAK_FIXTURE, Keccak256Hash(), "0x2a")
    assert baseline.leaf is not None
    assert prepared.public_inputs["storage_slot"] == "0x" + "00" * 32
    assert prepared.public_inputs["expected_storage_value"] == "0x" + "00" * 31 + "2a"
    assert prepared.private_inputs["account_proof_depth"] == 3
    assert prepared.private_inputs["storage_proof_depth"] == 1
    assert prepared.private_inputs["storage_value_active_bytes"] == [0x2A]
    assert prepared.private_inputs["storage_value_padded"] == [0] * 31 + [0x2A]
    mapped = to_noir_input_map(prepared)
    assert mapped["public_hash_variant_id"] == 1
    assert len(mapped["public_state_root"]) == 32
    assert len(mapped["public_contract_address"]) == 20
    assert len(mapped["public_storage_slot"]) == 32
    assert len(mapped["public_expected_storage_value"]) == 32
    assert mapped["private_storage_proof_depth"] == 1
    assert len(mapped["private_storage_node_rlp_bytes"]) == 1
    assert mapped["private_storage_value_active_len"] == 1
    assert [key for key in mapped if key.startswith("public_")] == [
        "public_hash_variant_id",
        "public_state_root",
        "public_contract_address",
        "public_storage_slot",
        "public_expected_storage_value",
    ]
    assert 1 + 32 + 20 + 32 + 32 == 117
    assert "public_storage_root" not in mapped
    assert "private_storage_root" not in mapped
    assert payload.address == prepared.public_inputs["contract_address"]


def test_retained_poseidon2_storage_preparation_and_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    assert hashlib.sha256(POSEIDON_FIXTURE.read_bytes()).hexdigest() == (
        "1d157bb2614ccd9baba694c9d8ac96dc7f496e5bad0b82d80ebd2bc19c71866a"
    )
    monkeypatch.setenv("THESIS_C_POSEIDON2_CMD", POSEIDON_CMD)
    payload, baseline, prepared = _prepared(
        POSEIDON_FIXTURE, Poseidon2Hash.from_environment(), "0x2a"
    )
    assert baseline.leaf is not None
    mapped = to_noir_input_map(prepared)
    assert mapped["public_hash_variant_id"] == 2
    assert "public_state_root_field" in mapped
    assert "private_storage_key_field" in mapped
    assert "private_storage_leaf_hash_field" in mapped
    assert "private_address_hash" in mapped
    assert "private_branch_child_hash_fields" in mapped
    assert "private_branch_children_fields" in mapped
    assert [key for key in mapped if key.startswith("public_")] == [
        "public_hash_variant_id",
        "public_state_root",
        "public_state_root_field",
        "public_contract_address",
        "public_storage_slot",
        "public_expected_storage_value",
    ]
    assert 1 + 32 + 1 + 20 + 32 + 32 == 118
    assert "public_storage_root" not in mapped
    assert "private_storage_root" not in mapped
    assert prepared.private_inputs["account_proof_depth"] == 2
    assert prepared.private_inputs["storage_proof_depth"] == 1
    assert prepared.private_inputs["storage_value_active_bytes"] == [0x2A]


def test_one_node_storage_leaf_binds_root_path_and_value() -> None:
    payload = load_proof_file(KECCAK_FIXTURE)[0]
    entry = payload.storage_proof[0]
    hash_variant = Keccak256Hash()
    key = derive_storage_trie_key(entry.key, hash_variant)
    root = hex_to_bytes(payload.raw_result["storageHash"])
    layout = parse_one_node_storage_leaf(
        hex_to_bytes(entry.proof[0]),
        expected_path=[nibble for byte in key for nibble in (byte >> 4, byte & 0x0F)],
        storage_root=root,
        hash_variant=hash_variant,
    )
    assert layout.leaf_node_len == len(hex_to_bytes(entry.proof[0]))
    assert layout.value_item.encoded_len == 1
    assert layout.value_payload_offset == layout.value_item.encoded_offset
    assert layout.active_value_bytes == b"*"
    assert layout.decoded_value == 42
    assert len(layout.path_nibbles) == 64
    assert storage_slot_bytes(entry.key) == b"\x00" * 32


def test_storage_preparation_rejects_cross_chain_storage_root_proof() -> None:
    payload = load_proof_file(KECCAK_FIXTURE)[0]
    baseline = verify_account_payload(payload, Keccak256Hash())
    assert baseline.ok
    other_leaf = rlp.encode(
        [
            hex_to_bytes(payload.storage_proof[0].proof[0])[1:34],
            rlp.encode(b"+")
        ]
    )
    mutated = deepcopy(payload)
    mutated.storage_proof[0].proof = ["0x" + other_leaf.hex()]
    with pytest.raises(ValueError, match="Baseline storage verification failed"):
        StorageSlotMembershipStatement().prepare([mutated], [baseline])


def test_storage_preparation_rejects_external_state_root_mismatch() -> None:
    payload = load_proof_file(KECCAK_FIXTURE)[0]
    baseline = verify_account_payload(payload, Keccak256Hash())
    assert baseline.ok
    payload.state_root = "0x" + "11" * 32
    with pytest.raises(ValueError, match="external_state_root_consistency_mismatch"):
        StorageSlotMembershipStatement().prepare([payload], [baseline])


def test_storage_leaf_rejects_canonical_zero() -> None:
    payload = load_proof_file(KECCAK_FIXTURE)[0]
    entry = payload.storage_proof[0]
    node = hex_to_bytes(entry.proof[0])
    compact = node[2:35]
    body = bytes([0x80 + len(compact)]) + compact + b"\x80"
    zero_node = bytes([0xC0 + len(body)]) + body
    with pytest.raises(ValueError, match="storage_value_must_be_nonzero"):
        parse_one_node_storage_leaf(
            zero_node,
            expected_path=[
                nibble
                for byte in derive_storage_trie_key(entry.key, Keccak256Hash())
                for nibble in (byte >> 4, byte & 0x0F)
            ],
            storage_root=Keccak256Hash().digest(zero_node),
            hash_variant=Keccak256Hash(),
        )


def test_storage_leaf_rejects_value_payload_longer_than_32_bytes() -> None:
    payload = load_proof_file(KECCAK_FIXTURE)[0]
    entry = payload.storage_proof[0]
    node = hex_to_bytes(entry.proof[0])
    compact = node[2:35]
    oversized = rlp.encode([compact, b"\x01" * 33])
    with pytest.raises(ValueError, match="UInt256 account scalar"):
        parse_one_node_storage_leaf(
            oversized,
            expected_path=[
                nibble
                for byte in derive_storage_trie_key(entry.key, Keccak256Hash())
                for nibble in (byte >> 4, byte & 0x0F)
            ],
            storage_root=Keccak256Hash().digest(oversized),
            hash_variant=Keccak256Hash(),
        )


@pytest.mark.parametrize(
    "mutation",
    ["empty", "multiple", "wrong_slot", "wrong_expected", "branch", "extension"],
)
def test_storage_preparation_rejects_malformed_or_unsupported_shape(
    mutation: str,
) -> None:
    payload = load_proof_file(KECCAK_FIXTURE)[0]
    baseline = verify_account_payload(payload, Keccak256Hash())
    assert baseline.ok
    mutated = deepcopy(payload)
    if mutation == "empty":
        mutated.storage_proof[0].proof = []
    elif mutation == "multiple":
        mutated.storage_proof.append(deepcopy(mutated.storage_proof[0]))
    elif mutation == "wrong_slot":
        mutated.storage_proof[0].key = "0x1"
    elif mutation == "wrong_expected":
        with pytest.raises(ValueError, match="expected_storage_value_mismatch"):
            StorageSlotMembershipStatement("0x2b").prepare([mutated], [baseline])
        return
    elif mutation == "branch":
        mutated.storage_proof[0].proof = ["0xc0"]
    else:
        node = hex_to_bytes(mutated.storage_proof[0].proof[0])
        mutated.storage_proof[0].proof = ["0x" + (node[:1] + b"\x00" + node[2:]).hex()]
    with pytest.raises(ValueError):
        StorageSlotMembershipStatement().prepare([mutated], [baseline])
