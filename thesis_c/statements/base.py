from __future__ import annotations

from abc import ABC, abstractmethod

from thesis_c.proof_inputs.schema import (
    BaselineVerificationResult,
    PreparedStatement,
    ProofPayload,
)


class ProofStatement(ABC):
    name: str
    required_payloads: int = 1

    @abstractmethod
    def prepare(
        self,
        payloads: list[ProofPayload],
        baseline_results: list[BaselineVerificationResult],
    ) -> PreparedStatement:
        raise NotImplementedError
