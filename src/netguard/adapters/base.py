"""Base adapter interface and NetworkFlow data model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class NetworkFlow:
    """A single network flow record."""

    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    duration: float
    bytes_fwd: int
    bytes_bwd: int
    packets_fwd: int
    packets_bwd: int
    tcp_flags: dict[str, int] = field(default_factory=dict)
    payload_entropy: float = 0.0

    @classmethod
    def from_dict(cls, event: dict[str, Any]) -> NetworkFlow:
        """Build a NetworkFlow from a raw dict (as produced by generators/Kafka)."""
        ts = event.get("timestamp")
        if isinstance(ts, (int, float)):
            ts_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        elif isinstance(ts, datetime):
            ts_dt = ts
        else:
            ts_dt = datetime.now(tz=timezone.utc)

        return cls(
            timestamp=ts_dt,
            src_ip=str(event.get("src_ip", "")),
            dst_ip=str(event.get("dst_ip", "")),
            src_port=int(event.get("src_port", 0)),
            dst_port=int(event.get("dst_port", 0)),
            protocol=str(event.get("protocol", "TCP")),
            duration=float(event.get("duration", 0.0)),
            bytes_fwd=int(event.get("bytes_fwd", 0)),
            bytes_bwd=int(event.get("bytes_bwd", 0)),
            packets_fwd=int(event.get("packets_fwd", 0)),
            packets_bwd=int(event.get("packets_bwd", 0)),
            tcp_flags=dict(event.get("tcp_flags") or {}),
            payload_entropy=float(event.get("payload_entropy", 0.0)),
        )


class SourceAdapter(ABC):
    """Abstract base class for network flow data sources."""

    @abstractmethod
    async def stream(self) -> AsyncIterator[NetworkFlow]:
        """Yield network flows from this source."""
        ...

    async def start(self) -> None:
        """Optional setup hook called before streaming begins."""

    async def stop(self) -> None:
        """Optional teardown hook called on shutdown."""

    def health_check(self) -> bool:
        """Return True if the adapter is healthy and ready to stream."""
        return True
