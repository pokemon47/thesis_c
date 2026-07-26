from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest

from thesis_c.baseline.account_verifier import (
    MAX_ACCOUNT_PROOF_DEPTH,
    MIN_ACCOUNT_PROOF_DEPTH,
    variable_depth_account_precheck,
)
from thesis_c.baseline.verifier_adapter import verify_account_payload
from thesis_c.hashes.keccak import Keccak256Hash
from thesis_c.hashes.poseidon2 import Poseidon2Hash
from thesis_c.proof_inputs.loaders import load_proof_file, load_proof_path


def _root() -> Path:
    return Path(__file__).resolve().parents[1]


def _workspace_root() -> Path:
    return _root().parents[1]


def _keccak_variable_fixture() -> Path:
    return _root() / "datasets/storage_slot_inclusion/keccak/controlled_contract_slot0_value42_depth3.json"


def _poseidon_variable_fixture() -> Path:
    return _root() / "datasets/storage_slot_inclusion/poseidon2/controlled_contract_slot0_value42_depth2.json"


def _keccak_depth4_fixture() -> Path:
    return _workspace_root() / "sample_proofs/proof_keccak_forest.json"


def _poseidon_depth4_fixture() -> Path:
    return _root() / "datasets/poseidon2/hoodi_block_9_account_proof_poseidon2.json"


def _prepared(path: Path, hash_variant):
    payload = load_proof_file(path)[0]
    return payload, variable_depth_account_precheck(payload, hash_variant)


def test_retained_real_variable_depth_fixtures(monkeypatch: pytest.MonkeyPatch) -> None:
    payload, result = _prepared(_keccak_variable_fixture(), Keccak256Hash())
    assert result.active_depth == 3
    assert result.terminal_node_len == len(bytes.fromhex(payload.account_proof[-1][2:]))
    assert result.baseline.ok

    monkeypatch.setenv(
        "THESIS_C_POSEIDON2_CMD",
        "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}",
    )
    payload, result = _prepared(
        _poseidon_variable_fixture(),
        Poseidon2Hash.from_environment(),
    )
    assert result.active_depth == 2
    assert result.baseline.ok


def test_existing_depth4_fixtures_remain_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    payload, result = _prepared(_keccak_depth4_fixture(), Keccak256Hash())
    assert result.active_depth == 4
    assert result.baseline.ok
    legacy = verify_account_payload(payload, Keccak256Hash())
    assert result.baseline == legacy
    assert result.baseline.leaf == legacy.leaf

    monkeypatch.setenv(
        "THESIS_C_POSEIDON2_CMD",
        "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}",
    )
    payload, result = _prepared(_poseidon_depth4_fixture(), Poseidon2Hash.from_environment())
    assert result.active_depth == 4
    assert result.baseline.ok
    legacy = verify_account_payload(payload, Poseidon2Hash.from_environment())
    assert result.baseline == legacy
    assert result.baseline.leaf == legacy.leaf


@pytest.mark.parametrize("depth", [0, 1, 5])
def test_depth_range_is_rejected(depth: int) -> None:
    payload = load_proof_file(_keccak_variable_fixture())[0]
    if depth <= 4:
        payload.account_proof = payload.account_proof[:depth]
    else:
        payload.account_proof = payload.account_proof + [payload.account_proof[-1]] * (depth - len(payload.account_proof))
    with pytest.raises(ValueError, match="unsupported_variable_account_proof_depth"):
        variable_depth_account_precheck(payload, Keccak256Hash())


@pytest.mark.parametrize(
    "mutation",
    [
        "early_leaf",
        "terminal_branch",
        "skipped_active_node",
        "wrong_root",
        "wrong_address",
        "wrong_child_link",
        "wrong_compact_path",
    ],
)
def test_direct_malformed_foundation_inputs_fail(mutation: str) -> None:
    payload = deepcopy(load_proof_file(_keccak_depth4_fixture())[0])
    nodes = [bytearray(bytes.fromhex(node[2:])) for node in payload.account_proof]
    if mutation == "early_leaf":
        payload.account_proof[1] = payload.account_proof[-1]
    elif mutation == "terminal_branch":
        payload.account_proof[-1] = payload.account_proof[0]
    elif mutation == "skipped_active_node":
        payload.account_proof.pop(2)
    elif mutation == "wrong_root" or mutation == "wrong_child_link":
        nodes[0][-1] ^= 1
        payload.account_proof[0] = "0x" + bytes(nodes[0]).hex()
    elif mutation == "wrong_address":
        address = bytearray(bytes.fromhex(payload.address[2:]))
        address[-1] ^= 1
        payload.address = "0x" + bytes(address).hex()
    elif mutation == "wrong_compact_path":
        nodes[-1][1] ^= 1
        payload.account_proof[-1] = "0x" + bytes(nodes[-1]).hex()

    with pytest.raises(ValueError):
        variable_depth_account_precheck(payload, Keccak256Hash())


@pytest.mark.parametrize("mutation", ["wrong_root", "wrong_address", "wrong_child_link", "wrong_compact_path"])
def test_poseidon2_direct_malformed_foundation_inputs_fail(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(
        "THESIS_C_POSEIDON2_CMD",
        "/Users/doodleaks/Developer/Thesis/besu_bonsai/ethereum/trie/build/install/besu-poseidon2-hash/bin/besu-poseidon2-hash {hex0x}",
    )
    payload = deepcopy(load_proof_file(_poseidon_variable_fixture())[0])
    nodes = [bytearray(bytes.fromhex(node[2:])) for node in payload.account_proof]
    if mutation in {"wrong_root", "wrong_child_link"}:
        nodes[0][-1] ^= 1
        payload.account_proof[0] = "0x" + bytes(nodes[0]).hex()
    elif mutation == "wrong_address":
        address = bytearray(bytes.fromhex(payload.address[2:]))
        address[-1] ^= 1
        payload.address = "0x" + bytes(address).hex()
    else:
        nodes[-1][1] ^= 1
        payload.account_proof[-1] = "0x" + bytes(nodes[-1]).hex()

    with pytest.raises(ValueError):
        variable_depth_account_precheck(payload, Poseidon2Hash.from_environment())


def test_authenticated_terminal_bounds_are_absolute() -> None:
    payload, result = _prepared(_keccak_variable_fixture(), Keccak256Hash())
    terminal = bytes.fromhex(payload.account_proof[-1][2:])
    assert 0 <= result.account_value_payload_offset < result.terminal_node_len
    assert (
        result.account_value_payload_offset + result.account_value_payload_len
        <= result.terminal_node_len
    )
    assert result.terminal_node_bytes == terminal
    assert len(result.node_lens) == MAX_ACCOUNT_PROOF_DEPTH
    assert len(result.node_kinds) == MAX_ACCOUNT_PROOF_DEPTH
    assert len(result.branch_child_hashes) == MAX_ACCOUNT_PROOF_DEPTH - 1
    assert len(result.branch_children) == MAX_ACCOUNT_PROOF_DEPTH - 1
    assert result.node_lens[3] == 0
    assert result.node_kinds[3] == 0
    assert result.branch_child_indices[2] == 0
    assert result.branch_child_hashes[2] == b"\x00" * 32
    assert result.branch_children[2] == (b"\x00" * 32,) * 16
    assert MIN_ACCOUNT_PROOF_DEPTH <= result.active_depth <= MAX_ACCOUNT_PROOF_DEPTH


def test_legacy_precheck_remains_exact_four() -> None:
    from thesis_c.baseline.verifier_adapter import bounded_account_precheck

    variable_payload = load_proof_file(_keccak_variable_fixture())[0]
    assert bounded_account_precheck(variable_payload)[0] is False
    depth4_payload = load_proof_file(_keccak_depth4_fixture())[0]
    assert bounded_account_precheck(depth4_payload)[0] is True
