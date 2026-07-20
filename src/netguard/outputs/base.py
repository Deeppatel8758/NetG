"""Abstract output sink and Alert data model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class Alert:
    """An anomaly detection alert."""

    id: str
    timestamp: datetime
    severity: str
    attack_type: str
    confidence: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""


class OutputSink(ABC):
    """Base class for alert output destinations."""

    def __init__(self, min_severity: str = "low") -> None:
        self._min_severity = min_severity

    @abstractmethod
    async def emit(self, alert: Alert) -> None:
        """Send an alert to this output sink."""
        ...

    def should_emit(self, alert: Alert) -> bool:
        """Return True if the alert meets the minimum severity threshold."""
        alert_level = SEVERITY_LEVELS.get(alert.severity, 0)
        min_level = SEVERITY_LEVELS.get(self._min_severity, 0)
        return alert_level >= min_level

    async def start(self) -> None:
        """Optional setup hook."""

    async def stop(self) -> None:
        """Optional teardown hook."""
