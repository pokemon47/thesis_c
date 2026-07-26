from __future__ import annotations

from pathlib import Path

import pytest
import rlp

from thesis_c.baseline.account_layout import (
    assert_canonical_uint_rlp_item,
    canonical_uint_rlp_item,
    parse_leaf_node_layout,
    parse_nested_account_layout,
    parse_rpc_quantity,
    u64_limbs_to_uint256,
    uint256_to_u64_limbs,
)
from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.noir.inputs import to_noir_input_map
from thesis_c.proof_inputs.loaders import load_proof_path
from thesis_c.proof_inputs.normalizer import hex_to_bytes
from thesis_c.statements.balance_verification import BalanceVerificationStatement


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _thesis_c_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _keccak_payload_and_baseline():
    payload = load_proof_path(_repo_root() / "sample_proofs" / "proof_keccak_forest.json")[0]
    baseline = verify_account_payload(payload, Keccak256Hash())
    assert baseline.ok
    assert baseline.leaf is not None
    return payload, baseline


def _poseidon2_payload_and_baseline(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "THESIS_C_POSEIDON2_CMD",
        "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/"
        "build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}",
    )
    payload = load_proof_path(
        _thesis_c_root() / "datasets" / "poseidon2" / "hoodi_block_9_account_proof_poseidon2.json"
    )[0]
    baseline = verify_account_payload(payload, Poseidon2Hash.from_environment())
    assert baseline.ok
    assert baseline.leaf is not None
    return payload, baseline


def _account_leaf_node_bytes() -> bytes:
    payload, _ = _keccak_payload_and_baseline()
    return hex_to_bytes(payload.account_proof[-1])


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        (0, "80"),
        (1, "01"),
        (0x7F, "7f"),
        (0x80, "8180"),
        (0xFF, "81ff"),
        (0x0100, "820100"),
        ((1 << 256) - 1, "a0" + "ff" * 32),
    ],
)
def test_canonical_balance_rlp_item(value: int, encoded: str) -> None:
    item = canonical_uint_rlp_item(value)
    assert item.hex() == encoded
    assert assert_canonical_uint_rlp_item(item) == value


@pytest.mark.parametrize("encoded", [b"\x00", b"\x81\x00", b"\x81\x01", b"\x82\x00\x80"])
def test_noncanonical_balance_rlp_item_rejected(encoded: bytes) -> None:
    with pytest.raises(ValueError):
        assert_canonical_uint_rlp_item(encoded)


def test_nested_account_layout_for_real_keccak_payload() -> None:
    leaf_node = _account_leaf_node_bytes()
    leaf_layout, account_layout = parse_nested_account_layout(leaf_node)
    payload, baseline = _keccak_payload_and_baseline()

    assert leaf_layout.outer_list.encoded_offset == 0
    assert leaf_layout.account_value_item.encoded_offset > leaf_layout.compact_path_item.encoded_offset
    assert account_layout.inner_list.encoded_offset == leaf_layout.account_value_item.payload_offset
    assert account_layout.balance.encoded_offset > account_layout.nonce.encoded_offset
    assert account_layout.storage_root.payload_len == 32
    assert account_layout.code_hash.payload_len == 32

    balance_item = leaf_node[
        account_layout.balance.encoded_offset : account_layout.balance.encoded_offset
        + account_layout.balance.encoded_len
    ]
    assert assert_canonical_uint_rlp_item(balance_item) == baseline.leaf.balance
    assert uint256_to_u64_limbs(payload.balance) == (0, 0, 243945, 6952882923431034880)
    assert u64_limbs_to_uint256(uint256_to_u64_limbs(payload.balance)) == parse_rpc_quantity(
        payload.balance
    )


@pytest.mark.parametrize(
    ("value", "limbs"),
    [
        (0, (0, 0, 0, 0)),
        (1, (0, 0, 0, 1)),
        ((1 << 64) + 1, (0, 0, 1, 1)),
        ((1 << 128) + 1, (0, 1, 0, 1)),
        ((1 << 192) + 1, (1, 0, 0, 1)),
        ((1 << 256) - 1, ((1 << 64) - 1, (1 << 64) - 1, (1 << 64) - 1, (1 << 64) - 1)),
    ],
)
def test_uint256_u64_limb_roundtrip(value: int, limbs: tuple[int, int, int, int]) -> None:
    assert uint256_to_u64_limbs(value) == limbs
    assert u64_limbs_to_uint256(limbs) == value


def test_leaf_layout_rejects_wrong_outer_item_count() -> None:
    malformed_leaf = rlp.encode([b"path", b"value", b"extra"])
    with pytest.raises(ValueError, match="exactly two"):
        parse_leaf_node_layout(malformed_leaf)


def test_account_layout_rejects_wrong_inner_field_count() -> None:
    malformed_account = rlp.encode([b"", b""])
    malformed_leaf = rlp.encode([b"path", malformed_account])
    with pytest.raises(ValueError, match="exactly four"):
        parse_nested_account_layout(malformed_leaf)


def test_account_layout_rejects_bad_storage_root_length() -> None:
    malformed_account = rlp.encode([b"", b"", b"\x11" * 31, b"\x22" * 32])
    malformed_leaf = rlp.encode([b"path", malformed_account])
    with pytest.raises(ValueError, match="storageRoot"):
        parse_nested_account_layout(malformed_leaf)


def test_balance_statement_prepares_real_keccak_inputs() -> None:
    payload, baseline = _keccak_payload_and_baseline()
    prepared = BalanceVerificationStatement().prepare([payload], [baseline])

    assert prepared.statement_name == "balance_verification"
    assert prepared.public_inputs["claimed_balance_limbs"] == uint256_to_u64_limbs(payload.balance)
    assert prepared.private_inputs["account_proof_depth"] == 4
    assert "balance" not in prepared.private_inputs
    assert "nonce" not in prepared.private_inputs
    assert "storage_root" not in prepared.private_inputs
    assert "code_hash" not in prepared.private_inputs

    noir_inputs = to_noir_input_map(prepared)
    assert list(noir_inputs)[:5] == [
        "witness_version",
        "public_state_root",
        "public_account_address",
        "public_claimed_balance_limbs",
        "public_hash_variant_id",
    ]
    assert noir_inputs["public_claimed_balance_limbs"] == list(uint256_to_u64_limbs(payload.balance))
    assert noir_inputs["private_account_proof_depth"] == 4
    assert "public_leaf_value_commitment" not in noir_inputs
    assert "public_state_root_field" not in noir_inputs
    assert "private_node_bytes" in noir_inputs
    assert "private_node_lengths" in noir_inputs
    assert "private_node_kinds" in noir_inputs
    assert "private_node_list_layouts" in noir_inputs
    assert "private_node_item_layouts" in noir_inputs
    assert "private_node_compact_layouts" in noir_inputs
    assert "private_selected_ref_layouts" in noir_inputs
    assert "private_selected_ref_bytes" in noir_inputs
    assert "private_selected_ref_lengths" in noir_inputs
    assert "private_selected_ref_kinds" in noir_inputs
    assert "private_terminal_value" in noir_inputs
    assert "private_terminal_value_len" in noir_inputs
    assert "private_leaf_outer_list_layout" in noir_inputs
    assert "private_leaf_compact_path_layout" in noir_inputs
    assert "private_leaf_account_value_layout" in noir_inputs
    assert "private_account_inner_list_layout" in noir_inputs
    assert "private_account_nonce_layout" in noir_inputs
    assert "private_account_balance_layout" in noir_inputs
    assert "private_account_storage_root_layout" in noir_inputs
    assert "private_account_code_hash_layout" in noir_inputs
    assert "private_branch_child_hash_fields" not in noir_inputs
    assert "private_branch_children_fields" not in noir_inputs
    assert "private_address_hash" not in noir_inputs
    assert "private_node_rlp_bytes" not in noir_inputs
    assert "private_balance" not in noir_inputs


def test_balance_statement_prepares_real_poseidon2_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload, baseline = _poseidon2_payload_and_baseline(monkeypatch)
    prepared = BalanceVerificationStatement().prepare([payload], [baseline])

    assert prepared.statement_name == "balance_verification"
    assert prepared.public_inputs["claimed_balance_limbs"] == uint256_to_u64_limbs(payload.balance)
    assert prepared.private_inputs["account_proof_depth"] == 4
    assert "balance" not in prepared.private_inputs
    assert "nonce" not in prepared.private_inputs
    assert "storage_root" not in prepared.private_inputs
    assert "code_hash" not in prepared.private_inputs

    noir_inputs = to_noir_input_map(prepared)
    assert list(noir_inputs)[:6] == [
        "witness_version",
        "public_state_root",
        "public_state_root_field",
        "public_account_address",
        "public_claimed_balance_limbs",
        "public_hash_variant_id",
    ]
    assert noir_inputs["public_claimed_balance_limbs"] == list(uint256_to_u64_limbs(payload.balance))
    assert noir_inputs["private_account_proof_depth"] == 4
    assert "public_leaf_value_commitment" not in noir_inputs
    assert noir_inputs["public_state_root_field"] == int(noir_inputs["public_state_root_field"])
    assert "private_node_bytes" in noir_inputs
    assert "private_node_lengths" in noir_inputs
    assert "private_node_kinds" in noir_inputs
    assert "private_node_list_layouts" in noir_inputs
    assert "private_node_item_layouts" in noir_inputs
    assert "private_node_compact_layouts" in noir_inputs
    assert "private_selected_ref_layouts" in noir_inputs
    assert "private_selected_ref_bytes" in noir_inputs
    assert "private_selected_ref_lengths" in noir_inputs
    assert "private_selected_ref_kinds" in noir_inputs
    assert "private_terminal_value" in noir_inputs
    assert "private_terminal_value_len" in noir_inputs
    assert "private_branch_child_hash_fields" not in noir_inputs
    assert "private_branch_children_fields" not in noir_inputs
    assert "private_address_hash" not in noir_inputs
    assert "private_leaf_outer_list_layout" in noir_inputs
    assert "private_leaf_compact_path_layout" in noir_inputs
    assert "private_leaf_account_value_layout" in noir_inputs
    assert "private_account_inner_list_layout" in noir_inputs
    assert "private_account_nonce_layout" in noir_inputs
    assert "private_account_balance_layout" in noir_inputs
    assert "private_account_storage_root_layout" in noir_inputs
    assert "private_account_code_hash_layout" in noir_inputs
    assert "private_node_rlp_bytes" not in noir_inputs
    assert "private_balance" not in noir_inputs


def test_explicit_wrong_claim_fails_production_preparation() -> None:
    payload, baseline = _keccak_payload_and_baseline()
    with pytest.raises(ValueError, match="Claimed balance"):
        BalanceVerificationStatement(claimed_balance=1).prepare([payload], [baseline])


def test_test_only_wrong_claim_can_render_witness_inputs() -> None:
    payload, baseline = _keccak_payload_and_baseline()
    prepared = BalanceVerificationStatement(
        claimed_balance=1,
        allow_wrong_claim_for_testing=True,
    ).prepare([payload], [baseline])

    noir_inputs = to_noir_input_map(prepared)
    assert noir_inputs["public_claimed_balance_limbs"] == list(uint256_to_u64_limbs(1))
