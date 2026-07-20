"""Tests for the MemoryStore feature store backend."""

from __future__ import annotations

import pytest

from netguard.features.store import MemoryStore, WindowStats


@pytest.fixture
def store():
    return MemoryStore()


class TestRecordAndWindow:
    async def test_empty_returns_zero_stats(self, store):
        stats = await store.window_stats("10.0.1.1", window_sec=60, now=100.0)
        assert stats == WindowStats()

    async def test_single_flow_counted(self, store):
        await store.record_flow(
            src_ip="10.0.1.1",
            dst_ip="10.0.1.2",
            dst_port=443,
            bytes_out=100,
            bytes_in=200,
            is_syn_only=False,
            timestamp=100.0,
        )
        stats = await store.window_stats("10.0.1.1", window_sec=60, now=100.0)
        assert stats.connection_count == 1
        assert stats.bytes_out == 100
        assert stats.bytes_in == 200
        assert stats.unique_dst_ips == 1
        assert stats.unique_dst_ports == 1
        assert stats.syn_only_count == 0

    async def test_unique_counts_dedupe(self, store):
        # Same src → three flows to two unique IPs, two unique ports
        for dst_ip, dst_port in [("1.1.1.1", 80), ("1.1.1.1", 443), ("2.2.2.2", 80)]:
            await store.record_flow(
                "10.0.1.1", dst_ip, dst_port, 10, 20, False, timestamp=100.0
            )
        stats = await store.window_stats("10.0.1.1", window_sec=60, now=100.0)
        assert stats.connection_count == 3
        assert stats.unique_dst_ips == 2
        assert stats.unique_dst_ports == 2

    async def test_syn_ratio(self, store):
        for is_syn in [True, True, True, False]:
            await store.record_flow("10.0.1.1", "1.1.1.1", 80, 40, 0, is_syn, 100.0)
        stats = await store.window_stats("10.0.1.1", window_sec=60, now=100.0)
        assert stats.connection_count == 4
        assert stats.syn_only_count == 3
        assert stats.syn_ratio == 0.75

    async def test_old_events_excluded(self, store):
        # Event at t=0, query at t=100 with window=60 → outside window
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 100, 200, False, timestamp=0.0)
        # Event at t=90 → inside 60s window from t=100
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 50, 100, False, timestamp=90.0)
        stats = await store.window_stats("10.0.1.1", window_sec=60, now=100.0)
        assert stats.connection_count == 1
        assert stats.bytes_out == 50

    async def test_windows_are_independent(self, store):
        # Event at t=20 → outside 60s window (cutoff=40), inside 300s window (cutoff=-200)
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 100, 0, False, timestamp=20.0)
        # Event at t=95 → inside both windows
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 100, 0, False, timestamp=95.0)
        s60 = await store.window_stats("10.0.1.1", 60, now=100.0)
        s300 = await store.window_stats("10.0.1.1", 300, now=100.0)
        assert s60.connection_count == 1
        assert s300.connection_count == 2

    async def test_per_ip_isolation(self, store):
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 100, 0, False, 100.0)
        await store.record_flow("10.0.1.2", "1.1.1.1", 80, 200, 0, False, 100.0)
        s1 = await store.window_stats("10.0.1.1", 60, now=100.0)
        s2 = await store.window_stats("10.0.1.2", 60, now=100.0)
        assert s1.bytes_out == 100
        assert s2.bytes_out == 200

    async def test_prune_bounds_memory(self, store):
        # Record 10 events far in the past
        for t in range(10):
            await store.record_flow("10.0.1.1", "1.1.1.1", 80, 1, 0, False, timestamp=float(t))
        # Now record one at t=1000 — old events should be pruned
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 1, 0, False, timestamp=1000.0)
        # Internal state should only carry the recent event
        state = store._ip_state["10.0.1.1"]
        assert len(state.events) == 1


class TestFirstSeen:
    async def test_first_time_returns_true(self, store):
        assert await store.is_new_and_mark("dst_ip", "10.0.1.1", "8.8.8.8") is True

    async def test_second_time_returns_false(self, store):
        await store.is_new_and_mark("dst_ip", "10.0.1.1", "8.8.8.8")
        assert await store.is_new_and_mark("dst_ip", "10.0.1.1", "8.8.8.8") is False

    async def test_different_src_ips_are_independent(self, store):
        await store.is_new_and_mark("dst_ip", "10.0.1.1", "8.8.8.8")
        assert await store.is_new_and_mark("dst_ip", "10.0.1.2", "8.8.8.8") is True

    async def test_different_kinds_are_independent(self, store):
        await store.is_new_and_mark("dst_ip", "10.0.1.1", "80")
        assert await store.is_new_and_mark("dst_port", "10.0.1.1", "80") is True


class TestWindowStatsFeatures:
    def test_syn_ratio_zero_when_no_connections(self):
        s = WindowStats()
        assert s.syn_ratio == 0.0

    def test_as_features_prefixed(self):
        s = WindowStats(unique_dst_ips=3, bytes_out=100, connection_count=2, syn_only_count=1)
        feats = s.as_features(window_sec=60)
        assert feats["w60_unique_dst_ips"] == 3.0
        assert feats["w60_bytes_out"] == 100.0
        assert feats["w60_syn_ratio"] == 0.5
