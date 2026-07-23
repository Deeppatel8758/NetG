"""Tests for the EnsembleScorer."""

from __future__ import annotations

import pytest

from netguard.models.base import AnomalyModel
from netguard.models.ensemble import EnsembleResult, EnsembleScorer


class _StubModel(AnomalyModel):
    """AnomalyModel that returns a fixed score. Optionally exposes attack labels."""

    def __init__(
        self,
        name: str,
        score_value: float,
        predicted_class: str | None = None,
        matched_rule: str | None = None,
    ) -> None:
        self._name = name
        self._score = score_value
        self.last_predicted_class = predicted_class
        self.matched_rule = matched_rule

    @property
    def name(self) -> str:
        return self._name

    def score(self, features: dict) -> float:
        return self._score


class TestEnsembleScoring:
    def test_empty_returns_zero(self):
        e = EnsembleScorer()
        result = e.score({})
        assert isinstance(result, EnsembleResult)
        assert result.final_score == 0.0

    def test_zero_weights_returns_zero(self):
        e = EnsembleScorer()
        e.add_model(_StubModel("A", 0.5), weight=0.0)
        assert e.score({}).final_score == 0.0

    def test_weighted_mean(self):
        e = EnsembleScorer()
        e.add_model(_StubModel("A", 0.2), weight=1.0)
        e.add_model(_StubModel("B", 0.8), weight=3.0)
        result = e.score({})
        # (0.2*1 + 0.8*3) / (1+3) = 2.6/4 = 0.65
        assert result.final_score == pytest.approx(0.65)

    def test_per_model_breakdown(self):
        e = EnsembleScorer()
        e.add_model(_StubModel("A", 0.2), weight=1.0)
        e.add_model(_StubModel("B", 0.8), weight=1.0)
        result = e.score({})
        assert result.per_model_scores == {"A": 0.2, "B": 0.8}

    def test_score_value_shim(self):
        e = EnsembleScorer()
        e.add_model(_StubModel("A", 0.5), weight=1.0)
        assert e.score_value({}) == pytest.approx(0.5)


class TestAttackTypeResolution:
    def test_xgboost_class_wins(self):
        e = EnsembleScorer()
        e.add_model(_StubModel("XGB", 0.9, predicted_class="port_scan"), weight=1.0)
        e.add_model(_StubModel("Rules", 0.4, matched_rule="brute_force"), weight=1.0)
        assert e.score({}).predicted_attack_type == "port_scan"

    def test_benign_xgboost_falls_back_to_rules(self):
        e = EnsembleScorer()
        e.add_model(_StubModel("XGB", 0.1, predicted_class="benign"), weight=1.0)
        e.add_model(_StubModel("Rules", 0.4, matched_rule="brute_force"), weight=1.0)
        assert e.score({}).predicted_attack_type == "brute_force"

    def test_no_signal_returns_none(self):
        e = EnsembleScorer()
        e.add_model(_StubModel("A", 0.1), weight=1.0)
        assert e.score({}).predicted_attack_type is None


class TestModelListAccess:
    def test_models_property_returns_copy(self):
        e = EnsembleScorer()
        stub = _StubModel("A", 0.5)
        e.add_model(stub, weight=1.0)
        models = e.models
        models.clear()  # Mutating the copy shouldn't affect the ensemble
        assert len(e.models) == 1
