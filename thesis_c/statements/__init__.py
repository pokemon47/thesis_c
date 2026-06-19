from __future__ import annotations

from thesis_c.statements.account_inclusion import AccountInclusionStatement
from thesis_c.statements.balance_verification import BalanceVerificationStatement
from thesis_c.statements.codehash_verification import CodeHashVerificationStatement
from thesis_c.statements.eoa_activity import EoaActivityStatement
from thesis_c.statements.storage_slot_membership import StorageSlotMembershipStatement

STATEMENT_REGISTRY = {
    "account_inclusion": AccountInclusionStatement,
    "balance_verification": BalanceVerificationStatement,
    "codehash_verification": CodeHashVerificationStatement,
    "eoa_activity": EoaActivityStatement,
    "storage_slot_membership": StorageSlotMembershipStatement,
}

__all__ = ["STATEMENT_REGISTRY"]
