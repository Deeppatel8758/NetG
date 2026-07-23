"""Adaptive threshold — rolling-percentile with fixed-value warmup fallback.

Behavior:
- strategy=="fixed": always return ``fixed_value``.
- strategy=="adaptive" (default): return ``fixed_value`` for the first
  ``warmup`` observations, then return ``np.percentile(window, base_percentile)``.

Backing store is a ``collections.deque(maxlen=window_size)`` — memory-bounded.
"""

from __future__ import annotations

from collections import deque

import numpy as np

from netguard.core.config import ThresholdConfig


class AdaptiveThreshold:
    """Score threshold that adapts to the recent score distribution."""

    def __init__(self, cfg: ThresholdConfig) -> None:
        self._cfg = cfg
        self._history: deque[float] = deque(maxlen=cfg.window_size)

    def update(self, score: float) -> None:
        """Record a new score observation."""
        self._history.append(float(score))

    def current(self) -> float:
        """Return the current alerting threshold."""
        if self._cfg.strategy == "fixed":
            return float(self._cfg.fixed_value)

        # Adaptive path: warmup then rolling percentile.
        if len(self._history) < self._cfg.warmup:
            return float(self._cfg.fixed_value)
        return float(np.percentile(np.fromiter(self._history, dtype=np.float64), self._cfg.base_percentile))

    def is_alert(self, score: float) -> bool:
        """Return True when ``score`` exceeds the current threshold."""
        return float(score) >= self.current()

    def __len__(self) -> int:
        return len(self._history)
