"""Variable active-depth account-proof foundation.

This module is intentionally separate from the legacy exact-four precheck.
It describes only the supported bounded language:
branch^(depth - 1) -> terminal leaf, with 2 <= depth <= 4.
"""

from __future__ import annotations

from dataclasses import dataclass

import rlp

from thesis_c.baseline.account_layout import (
    AccountValueLayout,
    LeafNodeLayout,
    parse_nested_account_layout,
)
from thesis_c.baseline.verifier_adapter import bytes_to_nibbles, decode_compact_with_flags
from thesis_c.hashes.base import HashVariant
from thesis_c.proof_inputs.normalizer import (
    ACCOUNT_PATH_NIBBLES,
    MAX_ACCOUNT_NODE_BYTES,
    MAX_ACCOUNT_PROOF_NODES,
    hex_to_bytes,
)
from thesis_c.proof_inputs.schema import BaselineVerificationResult, ProofPayload


MIN_ACCOUNT_PROOF_DEPTH = 2
MAX_ACCOUNT_PROOF_DEPTH = MAX_ACCOUNT_PROOF_NODES


@dataclass(frozen=True, slots=True)
class AuthenticatedTerminalResult:
    """Authenticated terminal data reusable by downstream account parsers."""

    active_depth: int
    terminal_node_bytes: bytes
    terminal_node_len: int
    account_value_payload_offset: int
    account_value_payload_len: int
    node_lens: tuple[int, ...]
    node_kinds: tuple[int, ...]
    branch_child_indices: tuple[int, ...]
    branch_child_hashes: tuple[bytes, ...]
    branch_children: tuple[tuple[bytes, ...], ...]
    path_nibbles: tuple[int, ...]
    leaf_path_nibbles: tuple[int, ...]
    leaf_layout: LeafNodeLayout
    account_layout: AccountValueLayout
    baseline: BaselineVerificationResult


def variable_depth_account_precheck(
    payload: ProofPayload, hash_variant: HashVariant
) -> AuthenticatedTerminalResult:
    """Validate a bounded variable-depth branch-chain account proof.

    This performs the full Python cryptographic walk, then applies the
    structural language and canonical fixed-capacity checks. It does not alter
    existing statement preparation; callers can adopt it independently.
    """

    depth = len(payload.account_proof)
    if not MIN_ACCOUNT_PROOF_DEPTH <= depth <= MAX_ACCOUNT_PROOF_DEPTH:
        raise ValueError(
            "unsupported_variable_account_proof_depth:"
            f"{depth}:expected_{MIN_ACCOUNT_PROOF_DEPTH}_{MAX_ACCOUNT_PROOF_DEPTH}"
        )

    try:
        proof_nodes = [hex_to_bytes(node_hex) for node_hex in payload.account_proof]
    except Exception as exc:
        raise ValueError(f"proof_hex_decode_error:{exc}") from exc

    for index, node in enumerate(proof_nodes):
        if len(node) > MAX_ACCOUNT_NODE_BYTES:
            raise ValueError(f"node_too_large:{index}:{len(node)}")
        try:
            decoded = rlp.decode(node)
        except Exception as exc:
            raise ValueError(f"node_rlp_decode_error:{index}:{exc}") from exc
        if not isinstance(decoded, list):
            raise ValueError(f"node_not_list:{index}")
        expected = 2 if index == depth - 1 else 17
        if len(decoded) != expected:
            kind = "terminal" if index == depth - 1 else "active_non_terminal"
            raise ValueError(
                f"{kind}_shape_mismatch:{index}:expected_{expected}_got_{len(decoded)}"
            )
        if index < depth - 1 and len(decoded) == 2:
            raise ValueError(f"extension_or_early_leaf:{index}")

    baseline = _baseline_account_verification(payload, hash_variant)
    if not baseline.ok:
        raise ValueError(f"baseline_account_verification_failed:{baseline.error}")

    address_hash = hash_variant.digest(hex_to_bytes(payload.address))
    path_nibbles = bytes_to_nibbles(address_hash)
    terminal = proof_nodes[-1]
    terminal_decoded = rlp.decode(terminal)
    compact_path = terminal_decoded[0]
    leaf_path_nibbles, is_leaf = decode_compact_with_flags(bytes(compact_path))
    if not is_leaf:
        raise ValueError("terminal_node_is_not_leaf")
    branch_nibbles = path_nibbles[: depth - 1]
    if leaf_path_nibbles != path_nibbles[depth - 1 :]:
        raise ValueError("terminal_compact_path_mismatch")
    if len(branch_nibbles) + len(leaf_path_nibbles) != ACCOUNT_PATH_NIBBLES:
        raise ValueError("account_path_does_not_consume_64_nibbles")

    leaf_layout, account_layout = parse_nested_account_layout(terminal)
    account_item = leaf_layout.account_value_item
    node_lens = tuple(len(node) for node in proof_nodes)
    node_kinds = tuple([0] * (depth - 1) + [2] + [0] * (4 - depth))
    active_indices, active_hashes, active_children = _active_branch_metadata(
        proof_nodes, path_nibbles, depth, hash_variant
    )
    branch_child_indices = tuple(
        active_indices + [0] * (MAX_ACCOUNT_PROOF_DEPTH - 1 - (depth - 1))
    )
    branch_child_hashes = tuple(
        active_hashes + [b"\x00" * 32] * (MAX_ACCOUNT_PROOF_DEPTH - 1 - (depth - 1))
    )
    branch_children = tuple(
        tuple(children)
        for children in (
            active_children
            + [[b"\x00" * 32 for _ in range(16)]]
            * (MAX_ACCOUNT_PROOF_DEPTH - 1 - (depth - 1))
        )
    )

    return AuthenticatedTerminalResult(
        active_depth=depth,
        terminal_node_bytes=terminal,
        terminal_node_len=len(terminal),
        account_value_payload_offset=account_item.payload_offset,
        account_value_payload_len=account_item.payload_len,
        node_lens=node_lens + (0,) * (MAX_ACCOUNT_PROOF_DEPTH - depth),
        node_kinds=node_kinds,
        branch_child_indices=branch_child_indices,
        branch_child_hashes=branch_child_hashes,
        branch_children=branch_children,
        path_nibbles=tuple(path_nibbles),
        leaf_path_nibbles=tuple(leaf_path_nibbles),
        leaf_layout=leaf_layout,
        account_layout=account_layout,
        baseline=baseline,
    )


def try_variable_depth_account_precheck(
    payload: ProofPayload, hash_variant: HashVariant
) -> tuple[bool, AuthenticatedTerminalResult | str]:
    """Non-throwing adapter for dataset and focused test harnesses."""

    try:
        return True, variable_depth_account_precheck(payload, hash_variant)
    except ValueError as exc:
        return False, str(exc)


def _baseline_account_verification(
    payload: ProofPayload,
    hash_variant: HashVariant,
) -> BaselineVerificationResult:
    """Run the existing full cryptographic walk without changing its API."""

    from thesis_c.baseline.verifier_adapter import verify_account_payload

    return verify_account_payload(payload, hash_variant)


def _active_branch_metadata(
    proof_nodes: list[bytes],
    path_nibbles: list[int],
    depth: int,
    hash_variant: HashVariant,
) -> tuple[list[int], list[bytes], list[list[bytes]]]:
    indices: list[int] = []
    hashes: list[bytes] = []
    children: list[list[bytes]] = []
    for index in range(depth - 1):
        decoded = rlp.decode(proof_nodes[index])
        nibble = path_nibbles[index]
        child = decoded[nibble]
        if not isinstance(child, (bytes, bytearray)) or len(child) == 0:
            raise ValueError(f"active_branch_child_missing:{index}")
        indices.append(nibble)
        normalized_children: list[bytes] = []
        for slot in decoded[:16]:
            if not isinstance(slot, (bytes, bytearray)):
                raise ValueError(f"branch_child_not_bytes:{index}")
            raw_slot = bytes(slot)
            if len(raw_slot) == 0:
                normalized_children.append(b"\x00" * 32)
            elif len(raw_slot) < 32:
                normalized_children.append(hash_variant.digest(raw_slot))
            elif len(raw_slot) == 32:
                normalized_children.append(raw_slot)
            else:
                raise ValueError(f"branch_child_too_large:{index}:{len(raw_slot)}")
        children.append(normalized_children)
        raw_child = bytes(child)
        hashes.append(
            hash_variant.digest(raw_child) if len(raw_child) < 32 else raw_child
        )
    return indices, hashes, children
