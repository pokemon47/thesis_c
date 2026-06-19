from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(slots=True)
class BenchmarkRecord:
    dataset_id: str
    statement: str
    hash_name: str
    backend: str
    address: str
    block_number: int | None
    proof_generation_time_s: float
    proof_verification_time_s: float
    witness_generation_time_s: float
    compile_time_s: float
    proof_size_bytes: int
    prove_peak_memory_bytes: int
    verify_peak_memory_bytes: int
    circuit_size_bytes: int | None
    constraint_count: int | None
    account_proof_node_count: int
    storage_proof_node_count: int
    raw_proof_byte_size: int
    verification_ok: bool
    branch_child_binding: str | None = None
    leaf_account_binding: str | None = None
    rlp_decoding: str | None = None
    mpt_verification_level: str | None = None
    status: str = "ok"
    error: str | None = None
    extras: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.extras is None:
            data.pop("extras", None)
        return data
