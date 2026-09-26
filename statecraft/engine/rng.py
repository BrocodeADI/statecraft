import random


class SeededRNG:
    """Deterministic RNG wrapper for simulation."""

    def __init__(self, seed: int):
        self.seed = seed
        self._rng = random.Random(seed)
        self._call_count = 0

    @property
    def call_count(self) -> int:
        return self._call_count

    def roll(self, probability: float) -> bool:
        """Consumes exactly one RNG draw and tests against probability."""
        self._call_count += 1
        return self._rng.random() < probability
