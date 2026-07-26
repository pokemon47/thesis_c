from __future__ import annotations

from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.statements.account_inclusion_anchored import AnchoredAccountInclusionStatement
from thesis_c.statements.account_inclusion_anchored_poseidon2 import AnchoredPoseidon2AccountInclusionStatement
from thesis_c.statements.balance_verification import BalanceVerificationStatement
from thesis_c.statements.balance_verification_anchored import AnchoredBalanceVerificationStatement
from thesis_c.statements.balance_verification_anchored_poseidon2 import AnchoredPoseidon2BalanceVerificationStatement
from thesis_c.statements.codehash_verification import CodeHashVerificationStatement
from thesis_c.statements.codehash_verification_anchored import AnchoredCodeHashVerificationStatement
from thesis_c.statements.codehash_verification_anchored_poseidon2 import AnchoredPoseidon2CodeHashVerificationStatement
from thesis_c.statements.eoa_activity import EoaActivityStatement
from thesis_c.statements.eoa_activity_anchored import AnchoredEoaActivityStatement
from thesis_c.statements.eoa_activity_anchored_poseidon2 import AnchoredPoseidon2EoaActivityStatement
from thesis_c.statements.storage_slot_membership import StorageSlotMembershipStatement

STATEMENT_REGISTRY = {
    "account_inclusion": AccountInclusionStatement,
    "account_inclusion_anchored": AnchoredAccountInclusionStatement,
    "account_inclusion_anchored_poseidon2": AnchoredPoseidon2AccountInclusionStatement,
    "balance_verification": BalanceVerificationStatement,
    "balance_verification_anchored": AnchoredBalanceVerificationStatement,
    "balance_verification_anchored_poseidon2": AnchoredPoseidon2BalanceVerificationStatement,
    "codehash_verification": CodeHashVerificationStatement,
    "codehash_verification_anchored": AnchoredCodeHashVerificationStatement,
    "codehash_verification_anchored_poseidon2": AnchoredPoseidon2CodeHashVerificationStatement,
    "eoa_activity": EoaActivityStatement,
    "eoa_activity_anchored": AnchoredEoaActivityStatement,
    "eoa_activity_anchored_poseidon2": AnchoredPoseidon2EoaActivityStatement,
    "storage_slot_membership": StorageSlotMembershipStatement,
}

__all__ = ["STATEMENT_REGISTRY"]
