"""Anomaly detection models."""

from netguard.models.base import AnomalyModel
from netguard.models.ensemble import EnsembleScorer

__all__ = ["AnomalyModel", "EnsembleScorer"]
