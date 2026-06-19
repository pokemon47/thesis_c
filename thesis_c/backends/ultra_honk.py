from __future__ import annotations

from thesis_c.backends.barretenberg import BarretenbergBackend, BarretenbergConfig


class UltraHonkBackend(BarretenbergBackend):
    def __init__(self, binary: str = "bb", oracle_hash: str = "keccak"):
        super().__init__(
            name="ultra_honk",
            config=BarretenbergConfig(
                scheme="ultra_honk",
                oracle_hash=oracle_hash,
                binary=binary,
            ),
        )
