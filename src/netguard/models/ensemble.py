"""Ensemble scorer combining multiple anomaly models.

Returns an EnsembleResult with the final weighted score, each model's
individual score, and a predicted attack type (preferring XGBoost's winning
class, falling back to the rules engine's matched rule).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netguard.models.base import AnomalyModel


@dataclass
class EnsembleResult:
    """Output of an ensemble scoring call."""

    final_score: float
    """Weighted average score in [0, 1]."""

    per_model_scores: dict[str, float] = field(default_factory=dict)
    """Individual model name → score (unweighted)."""

    predicted_attack_type: str | None = None
    """The winning attack label (e.g. 'port_scan') if any model produced one."""


class EnsembleScorer:
    """Combines scores from multiple AnomalyModel instances by weighted mean."""

    def __init__(self) -> None:
        self._models: list[tuple[AnomalyModel, float]] = []

    def add_model(self, model: AnomalyModel, weight: float = 1.0) -> None:
        self._models.append((model, weight))

    @property
    def models(self) -> list[tuple[AnomalyModel, float]]:
        return list(self._models)

    def score(self, features: dict) -> EnsembleResult:
        """Score all models and return the combined result."""
        if not self._models:
            return EnsembleResult(final_score=0.0)

        total_weight = sum(w for _, w in self._models)
        if total_weight == 0:
            return EnsembleResult(final_score=0.0)

        per_model: dict[str, float] = {}
        weighted_sum = 0.0
        for model, weight in self._models:
            s = model.score(features)
            per_model[model.name] = s
            weighted_sum += s * weight

        attack_type = self._resolve_attack_type()
        return EnsembleResult(
            final_score=weighted_sum / total_weight,
            per_model_scores=per_model,
            predicted_attack_type=attack_type,
        )

    def score_value(self, features: dict) -> float:
        """Backward-compat: return just the final score as a float."""
        return self.score(features).final_score

    def _resolve_attack_type(self) -> str | None:
        """XGBoost's non-benign winner beats the rules engine's matched rule.

        Reads the state each model recorded on its last score() call — cheap and
        avoids re-invoking predict.
        """
        for model, _ in self._models:
            # XGBoostClassifier writes last_predicted_class after each score()
            cls = getattr(model, "last_predicted_class", None)
            if cls and cls != "benign":
                return cls
        # Rules engine writes matched_rule after each score()
        for model, _ in self._models:
            rule = getattr(model, "matched_rule", None)
            if rule:
                return rule
        return None
