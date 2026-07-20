"""Integration tests for RedisStore.

Skipped automatically when Redis isn't reachable at ``REDIS_URL`` (default
``redis://localhost:6379/15`` — db 15 to avoid trampling on dev data).

Bring Redis up locally with:
    docker compose up -d redis
"""

from __future__ import annotations

import os

import pytest

from netguard.features.store import RedisStore, WindowStats

REDIS_URL = os.getenv("NETGUARD_TEST_REDIS_URL", "redis://localhost:6379/15")


async def _redis_reachable(url: str) -> bool:
    try:
        from redis.asyncio import Redis
    except ImportError:
        return False
    try:
        client = Redis.from_url(url, decode_responses=True, socket_connect_timeout=1)
        await client.ping()
        await client.aclose()
        return True
    except Exception:
        return False


@pytest.fixture
async def store():
    if not await _redis_reachable(REDIS_URL):
        pytest.skip(f"Redis not reachable at {REDIS_URL}")
    s = RedisStore(url=REDIS_URL)
    # Flush the test DB so state doesn't leak between tests
    await s._redis.flushdb()
    yield s
    await s._redis.flushdb()
    await s.close()


class TestRedisStoreContract:
    """The same contract MemoryStore tests cover, replayed against Redis."""

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
        stats = await store.window_stats("10.0.1.1", 60, now=100.0)
        assert stats.connection_count == 1
        assert stats.bytes_out == 100
        assert stats.bytes_in == 200
        assert stats.unique_dst_ips == 1
        assert stats.unique_dst_ports == 1

    async def test_old_events_excluded(self, store):
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 100, 200, False, timestamp=0.0)
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 50, 100, False, timestamp=90.0)
        stats = await store.window_stats("10.0.1.1", 60, now=100.0)
        assert stats.connection_count == 1
        assert stats.bytes_out == 50

    async def test_unique_counts(self, store):
        for dst_ip, dst_port in [("1.1.1.1", 80), ("1.1.1.1", 443), ("2.2.2.2", 80)]:
            await store.record_flow("10.0.1.1", dst_ip, dst_port, 10, 20, False, 100.0)
        stats = await store.window_stats("10.0.1.1", 60, now=100.0)
        assert stats.connection_count == 3
        assert stats.unique_dst_ips == 2
        assert stats.unique_dst_ports == 2

    async def test_syn_ratio(self, store):
        for is_syn in [True, True, True, False]:
            await store.record_flow("10.0.1.1", "1.1.1.1", 80, 40, 0, is_syn, 100.0)
        stats = await store.window_stats("10.0.1.1", 60, now=100.0)
        assert stats.syn_only_count == 3
        assert stats.syn_ratio == 0.75

    async def test_per_ip_isolation(self, store):
        await store.record_flow("10.0.1.1", "1.1.1.1", 80, 100, 0, False, 100.0)
        await store.record_flow("10.0.1.2", "1.1.1.1", 80, 200, 0, False, 100.0)
        s1 = await store.window_stats("10.0.1.1", 60, now=100.0)
        s2 = await store.window_stats("10.0.1.2", 60, now=100.0)
        assert s1.bytes_out == 100
        assert s2.bytes_out == 200


class TestRedisFirstSeen:
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
