"""Ensemble scorer combining multiple anomaly models."""

from __future__ import annotations

from netguard.models.base import AnomalyModel


class EnsembleScorer:
    """Combines scores from multiple models using weighted averaging."""

    def __init__(self) -> None:
        self._models: list[tuple[AnomalyModel, float]] = []

    def add_model(self, model: AnomalyModel, weight: float = 1.0) -> None:
        """Add a model to the ensemble with a given weight."""
        self._models.append((model, weight))

    def score(self, features: dict) -> float:
        """Compute weighted average score across all models."""
        if not self._models:
            return 0.0

        total_weight = sum(w for _, w in self._models)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(
            model.score(features) * weight for model, weight in self._models
        )
        return weighted_sum / total_weight
