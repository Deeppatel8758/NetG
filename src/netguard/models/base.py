"""Abstract base class for anomaly detection models."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AnomalyModel(ABC):
    """Base interface for all anomaly scoring models."""

    @abstractmethod
    def score(self, features: dict) -> float:
        """Score a feature vector. Returns a value in [0.0, 1.0] where 1.0 is most anomalous."""
        ...

    def update(self, features: dict, label: float | None = None) -> None:
        """Optional online learning update. Override for incremental models."""

    def load(self, path: str) -> None:
        """Load model weights/state from disk."""

    def save(self, path: str) -> None:
        """Save model weights/state to disk."""

    @property
    def name(self) -> str:
        """Human-readable model name."""
        return self.__class__.__name__

    @property
    def is_online(self) -> bool:
        """Whether this model supports online/incremental learning."""
        return False

    def health_check(self) -> dict:
        """Return model health status."""
        return {"model": self.name, "status": "ok", "is_online": self.is_online}
