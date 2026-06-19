"""The single source of randomness for the whole toolkit.

Every engine draws from a :class:`Rng` instance instead of calling the global
``random`` module directly. Two reasons:

* Reproducibility - a build can be replayed by re-using ``rng.seed``.
* Polymorphism - when no seed is supplied a fresh 64-bit seed is drawn from the
  OS, so running the same input twice produces different output.

Keeping all randomness behind one object also means a reviewer can audit
exactly how non-determinism enters the pipeline.
"""

from __future__ import annotations

import os
import random
from typing import Iterable, List, Optional, Sequence, TypeVar

T = TypeVar("T")


class Rng:
    """A thin, explicit wrapper around :class:`random.Random`.

    Parameters
    ----------
    seed:
        If ``None`` a fresh 64-bit seed is generated from :func:`os.urandom`.
        The resolved value is always available as :attr:`seed` so a build can be
        reproduced later.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        if seed is None:
            seed = int.from_bytes(os.urandom(8), "little")
        self.seed: int = seed
        self._random = random.Random(seed)

    def spawn(self, label: str) -> "Rng":
        """Return a child RNG deterministically derived from this one.

        Useful when a pass wants an independent stream that still depends on the
        parent seed (so the overall build stays reproducible).
        """

        derived = (self.seed ^ (hash(label) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
        return Rng(derived)

    # -- basic primitives -------------------------------------------------
    def randint(self, low: int, high: int) -> int:
        """Inclusive random integer in ``[low, high]``."""

        return self._random.randint(low, high)

    def randrange(self, stop: int) -> int:
        """Random integer in ``[0, stop)``."""

        return self._random.randrange(stop)

    def random(self) -> float:
        """Random float in ``[0.0, 1.0)``."""

        return self._random.random()

    def chance(self, probability: float) -> bool:
        """Return ``True`` with the given probability (0.0 - 1.0)."""

        return self._random.random() < probability

    def choice(self, items: Sequence[T]) -> T:
        """Pick one element uniformly at random."""

        return self._random.choice(items)

    def sample(self, items: Sequence[T], count: int) -> List[T]:
        """Pick ``count`` distinct elements without replacement."""

        return self._random.sample(list(items), count)

    def shuffle(self, items: List[T]) -> List[T]:
        """Shuffle ``items`` in place and also return it for convenience."""

        self._random.shuffle(items)
        return items

    def shuffled(self, items: Iterable[T]) -> List[T]:
        """Return a shuffled copy, leaving the input untouched."""

        out = list(items)
        self._random.shuffle(out)
        return out

    def bits(self, width: int) -> int:
        """Return a random unsigned integer with ``width`` bits."""

        return self._random.getrandbits(width)
