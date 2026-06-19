from __future__ import annotations

from abc import ABC, abstractmethod


class HashVariant(ABC):
    name: str

    @abstractmethod
    def digest(self, data: bytes) -> bytes:
        raise NotImplementedError

    def digest_hex(self, data: bytes) -> str:
        return "0x" + self.digest(data).hex()
