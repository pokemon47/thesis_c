from __future__ import annotations

from eth_utils import keccak

from .base import HashVariant


class Keccak256Hash(HashVariant):
    name = "keccak256"

    def digest(self, data: bytes) -> bytes:
        return keccak(data)
