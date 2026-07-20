"""End-to-end tests for the FeatureExtractor orchestrator."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netguard.adapters.base import NetworkFlow
from netguard.core.config import FeaturesConfig, StoreConfig
from netguard.features.extract import FeatureExtractor, build_store
from netguard.features.store import MemoryStore


def _flow(**overrides) -> NetworkFlow:
    defaults = dict(
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc),
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
    defaults.update(overrides)
    return NetworkFlow(**defaults)


@pytest.fixture
def extractor():
    return FeatureExtractor(store=MemoryStore(), windows_sec=(60, 300))


class TestBuildStore:
    def test_memory(self):
        store = build_store(StoreConfig(type="memory"))
        assert isinstance(store, MemoryStore)

    def test_unknown_raises(self):
        with pytest.raises(ValueError):
            build_store(StoreConfig(type="does-not-exist"))


class TestFromConfig:
    def test_defaults_to_memory(self):
        cfg = FeaturesConfig()
        ext = FeatureExtractor.from_config(cfg)
        assert isinstance(ext._store, MemoryStore)

    def test_respects_window_sizes(self):
        cfg = FeaturesConfig(window_sizes=[10, 60])
        ext = FeatureExtractor.from_config(cfg)
        assert ext._windows_sec == (10, 60)


class TestFeatureExtractor:
    async def test_first_flow_is_new(self, extractor):
        feats = await extractor.extract(_flow())
        assert feats["is_new_dst_ip"] == 1.0
        assert feats["is_new_dst_port"] == 1.0

    async def test_second_flow_same_dst_not_new(self, extractor):
        f = _flow()
        await extractor.extract(f)
        feats = await extractor.extract(f)
        assert feats["is_new_dst_ip"] == 0.0
        assert feats["is_new_dst_port"] == 0.0

    async def test_new_dst_ip_but_same_port(self, extractor):
        await extractor.extract(_flow(dst_ip="1.1.1.1"))
        feats = await extractor.extract(_flow(dst_ip="2.2.2.2"))  # same dst_port=443
        assert feats["is_new_dst_ip"] == 1.0
        assert feats["is_new_dst_port"] == 0.0

    async def test_windowed_features_present(self, extractor):
        feats = await extractor.extract(_flow())
        for window in (60, 300):
            for key in ("unique_dst_ips", "unique_dst_ports", "bytes_out", "bytes_in", "connection_count", "syn_ratio"):
                assert f"w{window}_{key}" in feats

    async def test_first_flow_has_empty_windows(self, extractor):
        # Store records AFTER computing windows, so first flow's windows are empty.
        feats = await extractor.extract(_flow())
        assert feats["w60_connection_count"] == 0.0
        assert feats["w60_bytes_out"] == 0.0

    async def test_windows_accumulate_across_flows(self, extractor):
        ts0 = datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc)
        ts1 = datetime(2026, 7, 20, 12, 0, 10, tzinfo=timezone.utc)
        await extractor.extract(_flow(timestamp=ts0, bytes_fwd=100))
        feats = await extractor.extract(_flow(timestamp=ts1, bytes_fwd=200))
        # Second flow sees the first in its 60s window
        assert feats["w60_connection_count"] == 1.0
        assert feats["w60_bytes_out"] == 100.0

    async def test_per_flow_features_still_present(self, extractor):
        feats = await extractor.extract(_flow())
        # Sanity: the flat feature dict includes the per-flow features too.
        assert "proto_tcp" in feats
        assert feats["proto_tcp"] == 1.0
        assert "payload_entropy" in feats
