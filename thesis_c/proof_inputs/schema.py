from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class StorageProofEntry:
    key: str
    value: str
    proof: list[str]


@dataclass(slots=True)
class ProofPayload:
    address: str
    balance: str
    code_hash: str
    nonce: str
    storage_hash: str
    account_proof: list[str]
    storage_proof: list[StorageProofEntry] = field(default_factory=list)
    block_number: int | None = None
    state_root: str | None = None
    source_file: str | None = None
    source_index: int | None = None
    raw_result: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AccountLeaf:
    nonce: int
    balance: int
    storage_root: str
    code_hash: str
    rlp_hex: str


@dataclass(slots=True)
class BaselineVerificationResult:
    ok: bool
    address: str
    hash_name: str
    state_root: str
    leaf: AccountLeaf | None
    account_proof_node_count: int
    storage_proof_node_count: int
    raw_proof_byte_size: int
    error: str | None = None


@dataclass(slots=True)
class StorageEntryVerificationResult:
    ok: bool
    key: str
    expected_value: str
    decoded_value: str | None
    decoded_value_int: int | None
    proof_node_count: int
    error: str | None = None


@dataclass(slots=True)
class StoragePayloadVerificationResult:
    ok: bool
    address: str
    hash_name: str
    state_root: str
    storage_root: str
    storage_root_matches_payload: bool
    account_ok: bool
    account_error: str | None
    entries: list[StorageEntryVerificationResult]
    account_proof_node_count: int
    storage_proof_node_count: int
    raw_proof_byte_size: int
    error: str | None = None


@dataclass(slots=True)
class PreparedStatement:
    statement_name: str
    public_inputs: dict[str, Any]
    private_inputs: dict[str, Any]
    metadata: dict[str, Any]
