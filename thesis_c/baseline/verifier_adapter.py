from __future__ import annotations

from dataclasses import dataclass

import rlp

from thesis_c.baseline.account_decoder import decode_account_leaf
from thesis_c.baseline.storage_decoder import (
    decode_storage_leaf_value_int,
    hex_quantity_to_int,
    int_to_hex_quantity,
)
from thesis_c.hashes.base import HashVariant
from thesis_c.proof_inputs.normalizer import (
    MAX_ACCOUNT_NODE_BYTES,
    MAX_ACCOUNT_PROOF_NODES,
    account_proof_node_count,
    hex_to_bytes,
    normalize_hex,
    raw_proof_byte_size,
    storage_proof_node_count,
)
from thesis_c.proof_inputs.schema import (
    BaselineVerificationResult,
    ProofPayload,
    StorageEntryVerificationResult,
    StoragePayloadVerificationResult,
    StorageProofEntry,
)


def bytes_to_nibbles(data: bytes) -> list[int]:
    out: list[int] = []
    for byte in data:
        out.append(byte >> 4)
        out.append(byte & 0x0F)
    return out


def decode_compact_with_flags(encoded: bytes) -> tuple[list[int], bool]:
    nibbles = bytes_to_nibbles(encoded)
    flag = nibbles[0]
    is_leaf = (flag & 2) != 0
    odd = (flag & 1) != 0
    path = nibbles[1:] if odd else nibbles[2:]
    return path, is_leaf


@dataclass(slots=True)
class ProofWalkResult:
    ok: bool
    value: bytes | None
    error: str | None = None


def bounded_account_precheck(payload: ProofPayload) -> tuple[bool, str | None]:
    if len(payload.account_proof) != MAX_ACCOUNT_PROOF_NODES:
        return (
            False,
            f"unsupported_proof_shape_nodes:{len(payload.account_proof)}",
        )
    try:
        nodes = [hex_to_bytes(node_hex) for node_hex in payload.account_proof]
    except Exception as exc:
        return False, f"proof_hex_decode_error:{exc}"
    for idx, node in enumerate(nodes):
        if len(node) > MAX_ACCOUNT_NODE_BYTES:
            return False, f"node_too_large:{idx}:{len(node)}"
        try:
            decoded = rlp.decode(node)
        except Exception as exc:
            return False, f"node_rlp_decode_error:{idx}:{exc}"
        if not isinstance(decoded, list):
            return False, f"node_not_list:{idx}"
        if idx < MAX_ACCOUNT_PROOF_NODES - 1 and len(decoded) != 17:
            return False, f"node_shape_mismatch:{idx}:expected_17_got_{len(decoded)}"
        if idx == MAX_ACCOUNT_PROOF_NODES - 1 and len(decoded) != 2:
            return False, f"node_shape_mismatch:{idx}:expected_2_got_{len(decoded)}"
    return True, None


def _walk_mpt_proof(
    proof_nodes: list[bytes], key: bytes, expected_root: bytes, hash_variant: HashVariant
) -> ProofWalkResult:
    path = bytes_to_nibbles(hash_variant.digest(key))
    path_index = 0
    current_hash = expected_root

    for node_rlp in proof_nodes:
        if hash_variant.digest(node_rlp) != current_hash:
            return ProofWalkResult(False, None, "Node hash mismatch while walking proof.")

        decoded = rlp.decode(node_rlp)
        if not isinstance(decoded, list):
            return ProofWalkResult(False, None, "RLP node is not a list.")

        # Branch node
        if len(decoded) == 17:
            if path_index == len(path):
                value = decoded[16]
                if not isinstance(value, (bytes, bytearray)) or len(value) == 0:
                    return ProofWalkResult(False, None, "Branch terminal value missing.")
                return ProofWalkResult(True, bytes(value))

            nibble = path[path_index]
            child = decoded[nibble]
            if not isinstance(child, (bytes, bytearray)) or len(child) == 0:
                return ProofWalkResult(False, None, "Branch child is empty.")
            child_bytes = bytes(child)
            current_hash = (
                hash_variant.digest(child_bytes)
                if len(child_bytes) < 32
                else child_bytes
            )
            path_index += 1
            continue

        # Leaf or extension node
        if len(decoded) == 2:
            raw_path = decoded[0]
            raw_value = decoded[1]
            if not isinstance(raw_path, (bytes, bytearray)) or not isinstance(
                raw_value, (bytes, bytearray)
            ):
                return ProofWalkResult(False, None, "Short node values are not bytes.")

            node_path, is_leaf = decode_compact_with_flags(bytes(raw_path))
            for nibble in node_path:
                if path_index >= len(path) or path[path_index] != nibble:
                    return ProofWalkResult(False, None, "Path nibble mismatch.")
                path_index += 1

            value_bytes = bytes(raw_value)
            if is_leaf:
                if path_index != len(path):
                    return ProofWalkResult(False, None, "Leaf ended before full key path.")
                return ProofWalkResult(True, value_bytes)

            current_hash = (
                hash_variant.digest(value_bytes) if len(value_bytes) < 32 else value_bytes
            )
            continue

        return ProofWalkResult(False, None, "Unsupported node shape.")

    return ProofWalkResult(False, None, "Proof walk ended without terminal value.")


def _walk_account_proof(
    proof_nodes: list[bytes], key: bytes, expected_root: bytes, hash_variant: HashVariant
) -> ProofWalkResult:
    return _walk_mpt_proof(proof_nodes, key, expected_root, hash_variant)


def _storage_key_to_bytes32(key: str) -> bytes:
    key_bytes = hex_to_bytes(key)
    if len(key_bytes) > 32:
        raise ValueError(f"Storage slot key exceeds 32 bytes: {len(key_bytes)}.")
    return key_bytes.rjust(32, b"\x00")


def _has_meaningful_storage_hash(value: str) -> bool:
    normalized = normalize_hex(value)
    return normalized not in {"0x", "0x0"}


def verify_storage_entry(
    entry: StorageProofEntry, storage_root: str, hash_variant: HashVariant
) -> StorageEntryVerificationResult:
    try:
        expected_value_int = hex_quantity_to_int(entry.value)
    except Exception as exc:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=entry.value,
            decoded_value=None,
            decoded_value_int=None,
            proof_node_count=len(entry.proof),
            error=f"Invalid storage entry value: {exc}",
        )
    expected_value = int_to_hex_quantity(expected_value_int)

    try:
        root_bytes = hex_to_bytes(storage_root)
    except Exception as exc:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=expected_value,
            decoded_value=None,
            decoded_value_int=None,
            proof_node_count=len(entry.proof),
            error=f"Invalid storage root: {exc}",
        )

    try:
        slot_key_bytes = _storage_key_to_bytes32(entry.key)
    except Exception as exc:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=expected_value,
            decoded_value=None,
            decoded_value_int=None,
            proof_node_count=len(entry.proof),
            error=f"Invalid storage slot key: {exc}",
        )

    try:
        proof_nodes = [hex_to_bytes(node_hex) for node_hex in entry.proof]
    except Exception as exc:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=expected_value,
            decoded_value=None,
            decoded_value_int=None,
            proof_node_count=len(entry.proof),
            error=f"Invalid storage proof node hex: {exc}",
        )
    if not proof_nodes:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=expected_value,
            decoded_value=None,
            decoded_value_int=None,
            proof_node_count=0,
            error="Empty storage proof.",
        )

    walk = _walk_mpt_proof(proof_nodes, slot_key_bytes, root_bytes, hash_variant)
    if not walk.ok or walk.value is None:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=expected_value,
            decoded_value=None,
            decoded_value_int=None,
            proof_node_count=len(proof_nodes),
            error=walk.error or "Storage proof walk failed.",
        )

    try:
        decoded_value_int = decode_storage_leaf_value_int(walk.value)
    except Exception as exc:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=expected_value,
            decoded_value=None,
            decoded_value_int=None,
            proof_node_count=len(proof_nodes),
            error=f"Failed to decode storage value: {exc}",
        )
    decoded_value = int_to_hex_quantity(decoded_value_int)

    if decoded_value_int != expected_value_int:
        return StorageEntryVerificationResult(
            ok=False,
            key=entry.key,
            expected_value=expected_value,
            decoded_value=decoded_value,
            decoded_value_int=decoded_value_int,
            proof_node_count=len(proof_nodes),
            error=(
                "Storage value mismatch: "
                f"expected {expected_value}, got {decoded_value}."
            ),
        )

    return StorageEntryVerificationResult(
        ok=True,
        key=entry.key,
        expected_value=expected_value,
        decoded_value=decoded_value,
        decoded_value_int=decoded_value_int,
        proof_node_count=len(proof_nodes),
        error=None,
    )


def verify_account_payload(
    payload: ProofPayload, hash_variant: HashVariant
) -> BaselineVerificationResult:
    proof_nodes = [hex_to_bytes(node_hex) for node_hex in payload.account_proof]
    address_bytes = hex_to_bytes(payload.address)

    if not proof_nodes:
        return BaselineVerificationResult(
            ok=False,
            address=payload.address,
            hash_name=hash_variant.name,
            state_root="0x",
            leaf=None,
            account_proof_node_count=account_proof_node_count(payload),
            storage_proof_node_count=storage_proof_node_count(payload),
            raw_proof_byte_size=raw_proof_byte_size(payload),
            error="Empty accountProof.",
        )

    state_root = hash_variant.digest(proof_nodes[0])
    walk = _walk_account_proof(proof_nodes, address_bytes, state_root, hash_variant)

    leaf = None
    if walk.ok and walk.value is not None:
        try:
            leaf = decode_account_leaf(walk.value)
        except Exception as exc:  # pragma: no cover - defensive for malformed leaves
            return BaselineVerificationResult(
                ok=False,
                address=payload.address,
                hash_name=hash_variant.name,
                state_root="0x" + state_root.hex(),
                leaf=None,
                account_proof_node_count=account_proof_node_count(payload),
                storage_proof_node_count=storage_proof_node_count(payload),
                raw_proof_byte_size=raw_proof_byte_size(payload),
                error=f"Failed to decode account leaf: {exc}",
            )

    return BaselineVerificationResult(
        ok=walk.ok,
        address=payload.address,
        hash_name=hash_variant.name,
        state_root="0x" + state_root.hex(),
        leaf=leaf,
        account_proof_node_count=account_proof_node_count(payload),
        storage_proof_node_count=storage_proof_node_count(payload),
        raw_proof_byte_size=raw_proof_byte_size(payload),
        error=walk.error,
    )


def verify_storage_payload(
    payload: ProofPayload, hash_variant: HashVariant
) -> StoragePayloadVerificationResult:
    account_result = verify_account_payload(payload, hash_variant)
    storage_root = (
        account_result.leaf.storage_root
        if account_result.leaf is not None
        else normalize_hex(payload.storage_hash)
    )

    storage_root_matches_payload = True
    if account_result.leaf is not None and _has_meaningful_storage_hash(payload.storage_hash):
        storage_root_matches_payload = normalize_hex(payload.storage_hash) == normalize_hex(
            account_result.leaf.storage_root
        )

    entries: list[StorageEntryVerificationResult] = []
    error: str | None = None
    if not account_result.ok or account_result.leaf is None:
        error = f"Account verification failed: {account_result.error or 'unknown_error'}"
    elif not storage_root_matches_payload:
        error = "Storage root mismatch between account leaf and payload.storage_hash."
    elif not payload.storage_proof:
        error = "No storageProof entries."
    else:
        entries = [
            verify_storage_entry(entry, account_result.leaf.storage_root, hash_variant)
            for entry in payload.storage_proof
        ]
        if any(not entry.ok for entry in entries):
            error = "One or more storageProof entries failed verification."

    ok = (
        account_result.ok
        and account_result.leaf is not None
        and storage_root_matches_payload
        and bool(entries)
        and all(entry.ok for entry in entries)
    )

    return StoragePayloadVerificationResult(
        ok=ok,
        address=payload.address,
        hash_name=hash_variant.name,
        state_root=account_result.state_root,
        storage_root=storage_root,
        storage_root_matches_payload=storage_root_matches_payload,
        account_ok=account_result.ok,
        account_error=account_result.error,
        entries=entries,
        account_proof_node_count=account_result.account_proof_node_count,
        storage_proof_node_count=account_result.storage_proof_node_count,
        raw_proof_byte_size=account_result.raw_proof_byte_size,
        error=error,
    )
