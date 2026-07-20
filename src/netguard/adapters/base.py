"""Base adapter interface and NetworkFlow data model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime


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
    tcp_flags: dict[str, bool] = field(default_factory=dict)
    payload_entropy: float = 0.0


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
