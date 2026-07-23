"""Tests for feature_spec — frozen order, drift guard, vector projection."""

from __future__ import annotations

from datetime import datetime, timezone

import numpy as np
import pytest

from netguard.adapters.base import NetworkFlow
from netguard.features.extract import FeatureExtractor
from netguard.features.store import MemoryStore
from netguard.models.feature_spec import (
    ATTACK_CLASSES,
    CLASS_COUNT,
    FEATURE_COUNT,
    FEATURE_ORDER,
    to_vector,
)


def _sample_flow() -> NetworkFlow:
    return NetworkFlow(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        src_ip="10.0.1.10",
        dst_ip="8.8.8.8",
        src_port=45123,
        dst_port=443,
        protocol="TCP",
        duration=1.5,
        bytes_fwd=1000,
        bytes_bwd=2000,
        packets_fwd=10,
        packets_bwd=20,
        tcp_flags={"SYN": 1, "ACK": 15, "FIN": 1, "PSH": 5},
        payload_entropy=5.0,
    )


class TestFeatureSpec:
    def test_no_duplicates(self):
        assert len(FEATURE_ORDER) == len(set(FEATURE_ORDER))

    def test_count_matches(self):
        assert FEATURE_COUNT == len(FEATURE_ORDER)


class TestAttackClasses:
    def test_no_duplicates(self):
        assert len(ATTACK_CLASSES) == len(set(ATTACK_CLASSES))

    def test_benign_is_first(self):
        # Anomaly score = 1 - probs[0], so benign must be class 0.
        assert ATTACK_CLASSES[0] == "benign"

    def test_count_matches(self):
        assert CLASS_COUNT == len(ATTACK_CLASSES)


class TestToVector:
    def test_shape_and_dtype(self):
        vec = to_vector({name: float(i) for i, name in enumerate(FEATURE_ORDER)})
        assert vec.shape == (FEATURE_COUNT,)
        assert vec.dtype == np.float32

    def test_missing_keys_default_zero(self):
        vec = to_vector({})
        assert np.all(vec == 0.0)

    def test_order_preserved(self):
        feats = {name: float(i) for i, name in enumerate(FEATURE_ORDER)}
        vec = to_vector(feats)
        assert vec[0] == 0.0
        assert vec[-1] == float(FEATURE_COUNT - 1)

    def test_extra_keys_ignored(self):
        feats = {"bytes_bwd": 5.0, "nonsense_key": 999.0}
        vec = to_vector(feats)
        assert vec[FEATURE_ORDER.index("bytes_bwd")] == 5.0
        assert 999.0 not in vec


class TestFeatureDriftGuard:
    """The freeze contract: FeatureExtractor output must match FEATURE_ORDER exactly."""

    async def test_extractor_keys_match_feature_order(self):
        ext = FeatureExtractor(store=MemoryStore(), windows_sec=(60, 300))
        feats = await ext.extract(_sample_flow())
        assert set(feats.keys()) == set(FEATURE_ORDER), (
            f"Feature drift! "
            f"missing_in_extractor={set(FEATURE_ORDER) - set(feats.keys())}, "
            f"missing_in_spec={set(feats.keys()) - set(FEATURE_ORDER)}"
        )

    async def test_extractor_output_round_trips_to_vector(self):
        ext = FeatureExtractor(store=MemoryStore(), windows_sec=(60, 300))
        feats = await ext.extract(_sample_flow())
        vec = to_vector(feats)
        assert vec.shape == (FEATURE_COUNT,)
        # No NaNs or infs — models will choke on them
        assert np.all(np.isfinite(vec))
