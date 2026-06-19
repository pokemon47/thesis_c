from __future__ import annotations

from thesis_c.backends.ultra_honk import UltraHonkBackend
from thesis_c.backends.ultra_plonk import UltraPlonkBackend

BACKEND_REGISTRY = {
    "ultra_plonk": UltraPlonkBackend,
    "ultra_honk": UltraHonkBackend,
}

__all__ = ["BACKEND_REGISTRY"]
