"""Feature store — rolling per-IP aggregates and first-seen tracking.

Two backends implement the same contract:
- ``MemoryStore``: in-process dicts + deques. Used in demo mode and tests.
- ``RedisStore``: Redis-backed sorted sets + sets. Used in production.

The store is intentionally narrow: it records one event per flow and answers
two questions — "what has this src_ip done in the last N seconds?" and "is this
(src, dst) or (src, port) combination new?"
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field


@dataclass
class WindowStats:
    """Rolling aggregates for a single source IP over one window."""

    unique_dst_ips: int = 0
    unique_dst_ports: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    connection_count: int = 0
    syn_only_count: int = 0

    @property
    def syn_ratio(self) -> float:
        if self.connection_count == 0:
            return 0.0
        return self.syn_only_count / self.connection_count

    def as_features(self, window_sec: int) -> dict[str, float]:
        """Flatten into a feature dict prefixed by window size (e.g. w60_bytes_out)."""
        prefix = f"w{window_sec}_"
        return {
            f"{prefix}unique_dst_ips": float(self.unique_dst_ips),
            f"{prefix}unique_dst_ports": float(self.unique_dst_ports),
            f"{prefix}bytes_out": float(self.bytes_out),
            f"{prefix}bytes_in": float(self.bytes_in),
            f"{prefix}connection_count": float(self.connection_count),
            f"{prefix}syn_ratio": self.syn_ratio,
        }


class FeatureStore(ABC):
    """Async interface for per-source-IP rolling aggregates + first-seen sets."""

    @abstractmethod
    async def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        bytes_out: int,
        bytes_in: int,
        is_syn_only: bool,
        timestamp: float,
    ) -> None:
        """Record one flow event for later windowed queries."""

    @abstractmethod
    async def window_stats(self, src_ip: str, window_sec: int, now: float) -> WindowStats:
        """Return aggregates for ``src_ip`` over the last ``window_sec`` seconds."""

    @abstractmethod
    async def is_new_and_mark(self, kind: str, src_ip: str, value: str | int) -> bool:
        """Return True if (src_ip, kind, value) has never been seen; then mark it seen.

        ``kind`` is a free-form namespace, typically ``"dst_ip"`` or ``"dst_port"``.
        """

    async def close(self) -> None:
        """Release any backing resources. Default: no-op."""


# ---------------------------------------------------------------------------
# MemoryStore
# ---------------------------------------------------------------------------


@dataclass
class _FlowEvent:
    ts: float
    dst_ip: str
    dst_port: int
    bytes_out: int
    bytes_in: int
    is_syn_only: bool


@dataclass
class _MemoryIpState:
    events: deque[_FlowEvent] = field(default_factory=deque)


# Max window we prune to; matches the largest supported window (5min).
_MAX_WINDOW_SEC = 300


class MemoryStore(FeatureStore):
    """In-process feature store — sufficient for demo mode and tests.

    Not thread-safe. Assumed to be called from a single asyncio task
    (the Faust stream processor).
    """

    def __init__(self, max_window_sec: int = _MAX_WINDOW_SEC) -> None:
        self._max_window_sec = max_window_sec
        self._ip_state: dict[str, _MemoryIpState] = {}
        self._seen: dict[str, set[str]] = {}

    async def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        bytes_out: int,
        bytes_in: int,
        is_syn_only: bool,
        timestamp: float,
    ) -> None:
        state = self._ip_state.setdefault(src_ip, _MemoryIpState())
        state.events.append(
            _FlowEvent(
                ts=timestamp,
                dst_ip=dst_ip,
                dst_port=dst_port,
                bytes_out=bytes_out,
                bytes_in=bytes_in,
                is_syn_only=is_syn_only,
            )
        )
        self._prune(state, timestamp)

    async def window_stats(self, src_ip: str, window_sec: int, now: float) -> WindowStats:
        state = self._ip_state.get(src_ip)
        if state is None:
            return WindowStats()

        # Lazy prune on read so callers on quiet IPs still see accurate windows.
        self._prune(state, now)

        cutoff = now - window_sec
        stats = WindowStats()
        unique_ips: set[str] = set()
        unique_ports: set[int] = set()
        for ev in state.events:
            if ev.ts < cutoff:
                continue
            unique_ips.add(ev.dst_ip)
            unique_ports.add(ev.dst_port)
            stats.bytes_out += ev.bytes_out
            stats.bytes_in += ev.bytes_in
            stats.connection_count += 1
            if ev.is_syn_only:
                stats.syn_only_count += 1
        stats.unique_dst_ips = len(unique_ips)
        stats.unique_dst_ports = len(unique_ports)
        return stats

    async def is_new_and_mark(self, kind: str, src_ip: str, value: str | int) -> bool:
        namespace = f"{kind}:{src_ip}"
        seen = self._seen.setdefault(namespace, set())
        key = str(value)
        if key in seen:
            return False
        seen.add(key)
        return True

    def _prune(self, state: _MemoryIpState, now: float) -> None:
        cutoff = now - self._max_window_sec
        events = state.events
        while events and events[0].ts < cutoff:
            events.popleft()


# ---------------------------------------------------------------------------
# RedisStore
# ---------------------------------------------------------------------------


_FLOWS_KEY = "flows:{src_ip}"
_SEEN_KEY = "seen:{kind}:{src_ip}"

# Idle keys expire this long after the last write — twice the largest window so
# a flow that just missed a query still counts, without hoarding cold IPs forever.
_IDLE_TTL_SEC = _MAX_WINDOW_SEC * 2


def _encode_event(ev: _FlowEvent) -> str:
    """Pack a flow event into a compact CSV-ish string for Redis sorted-set members.

    We can't just use the timestamp as the member (many flows share a timestamp),
    so members carry both the score and the payload.
    """
    return f"{ev.ts}|{ev.dst_ip}|{ev.dst_port}|{ev.bytes_out}|{ev.bytes_in}|{int(ev.is_syn_only)}"


def _decode_event(raw: str) -> _FlowEvent:
    ts, dst_ip, dst_port, bytes_out, bytes_in, is_syn = raw.split("|")
    return _FlowEvent(
        ts=float(ts),
        dst_ip=dst_ip,
        dst_port=int(dst_port),
        bytes_out=int(bytes_out),
        bytes_in=int(bytes_in),
        is_syn_only=bool(int(is_syn)),
    )


class RedisStore(FeatureStore):
    """Redis-backed feature store using sorted sets + regular sets.

    Key schema:
    - ``flows:{src_ip}`` (Sorted Set) — flow events scored by timestamp.
    - ``seen:{kind}:{src_ip}`` (Set) — first-seen tracking per namespace.

    All keys receive a rolling TTL on every write.
    """

    def __init__(self, url: str = "redis://localhost:6379/0", max_window_sec: int = _MAX_WINDOW_SEC) -> None:
        # Import here so tests that never touch Redis don't need the client installed.
        from redis.asyncio import Redis

        self._max_window_sec = max_window_sec
        self._redis: Redis = Redis.from_url(url, decode_responses=True)

    async def record_flow(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        bytes_out: int,
        bytes_in: int,
        is_syn_only: bool,
        timestamp: float,
    ) -> None:
        key = _FLOWS_KEY.format(src_ip=src_ip)
        event = _FlowEvent(
            ts=timestamp,
            dst_ip=dst_ip,
            dst_port=dst_port,
            bytes_out=bytes_out,
            bytes_in=bytes_in,
            is_syn_only=is_syn_only,
        )
        cutoff = timestamp - self._max_window_sec

        pipe = self._redis.pipeline(transaction=False)
        pipe.zadd(key, {_encode_event(event): timestamp})
        pipe.zremrangebyscore(key, "-inf", cutoff)
        pipe.expire(key, _IDLE_TTL_SEC)
        await pipe.execute()

    async def window_stats(self, src_ip: str, window_sec: int, now: float) -> WindowStats:
        key = _FLOWS_KEY.format(src_ip=src_ip)
        cutoff = now - window_sec
        raw = await self._redis.zrangebyscore(key, cutoff, "+inf")

        stats = WindowStats()
        unique_ips: set[str] = set()
        unique_ports: set[int] = set()
        for member in raw:
            ev = _decode_event(member)
            unique_ips.add(ev.dst_ip)
            unique_ports.add(ev.dst_port)
            stats.bytes_out += ev.bytes_out
            stats.bytes_in += ev.bytes_in
            stats.connection_count += 1
            if ev.is_syn_only:
                stats.syn_only_count += 1
        stats.unique_dst_ips = len(unique_ips)
        stats.unique_dst_ports = len(unique_ports)
        return stats

    async def is_new_and_mark(self, kind: str, src_ip: str, value: str | int) -> bool:
        key = _SEEN_KEY.format(kind=kind, src_ip=src_ip)
        # SADD returns the number of new members (0 or 1).
        added = await self._redis.sadd(key, str(value))
        if added:
            await self._redis.expire(key, _IDLE_TTL_SEC)
        return bool(added)

    async def close(self) -> None:
        await self._redis.aclose()
