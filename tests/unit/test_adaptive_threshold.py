"""Tests for AdaptiveThreshold."""

from __future__ import annotations

import numpy as np
import pytest

from netguard.core.config import ThresholdConfig
from netguard.threshold.adaptive import AdaptiveThreshold


class TestFixedStrategy:
    def test_always_returns_fixed_value(self):
        t = AdaptiveThreshold(ThresholdConfig(strategy="fixed", fixed_value=0.6))
        assert t.current() == 0.6
        # Even after many observations
        for _ in range(500):
            t.update(0.1)
        assert t.current() == 0.6


class TestAdaptiveWarmup:
    def test_returns_fixed_before_warmup(self):
        t = AdaptiveThreshold(ThresholdConfig(strategy="adaptive", fixed_value=0.7, warmup=100))
        for _ in range(50):
            t.update(0.95)
        # Below warmup → still fixed_value
        assert t.current() == 0.7

    def test_switches_to_percentile_after_warmup(self):
        cfg = ThresholdConfig(
            strategy="adaptive",
            fixed_value=0.7,
            warmup=100,
            base_percentile=95.0,
            window_size=1000,
        )
        t = AdaptiveThreshold(cfg)
        # Feed a known distribution
        rng = np.random.default_rng(0)
        samples = rng.uniform(0.0, 1.0, size=500)
        for s in samples:
            t.update(s)
        expected = float(np.percentile(samples, 95.0))
        assert t.current() == pytest.approx(expected, abs=1e-6)

    def test_window_evicts_old_scores(self):
        cfg = ThresholdConfig(
            strategy="adaptive", fixed_value=0.0, warmup=10, base_percentile=50.0, window_size=100
        )
        t = AdaptiveThreshold(cfg)
        # First fill with high scores, then flood with low ones
        for _ in range(100):
            t.update(1.0)
        # Add 100 low scores → old 1.0s should be evicted
        for _ in range(100):
            t.update(0.0)
        # p50 of [0.0]*100 = 0.0
        assert t.current() == pytest.approx(0.0, abs=1e-6)


class TestIsAlert:
    def test_score_above_threshold_alerts(self):
        t = AdaptiveThreshold(ThresholdConfig(strategy="fixed", fixed_value=0.5))
        assert t.is_alert(0.6) is True
        assert t.is_alert(0.4) is False

    def test_score_equal_to_threshold_alerts(self):
        t = AdaptiveThreshold(ThresholdConfig(strategy="fixed", fixed_value=0.5))
        assert t.is_alert(0.5) is True


class TestLen:
    def test_len_reflects_history_size(self):
        t = AdaptiveThreshold(ThresholdConfig(window_size=50))
        assert len(t) == 0
        for _ in range(30):
            t.update(0.5)
        assert len(t) == 30
        for _ in range(100):
            t.update(0.5)
        assert len(t) == 50
