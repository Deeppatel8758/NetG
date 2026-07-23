"""Unit tests for HalfSpaceTreesModel."""

from __future__ import annotations

import pytest

from netguard.models.half_space_trees import HalfSpaceTreesModel


@pytest.fixture
def model():
    return HalfSpaceTreesModel(n_trees=10, height=6, window_size=100, seed=42)


class TestHalfSpaceTrees:
    def test_score_in_unit_interval(self, model):
        score = model.score({"a": 1.0, "b": 2.0, "c": 3.0})
        assert 0.0 <= score <= 1.0

    def test_is_online(self, model):
        assert model.is_online is True

    def test_name(self, model):
        assert model.name == "HalfSpaceTreesModel"

    def test_outlier_scored_higher_than_typical(self, model):
        # HST needs varied inputs to build meaningful mass distributions.
        import random

        rng = random.Random(0)
        for _ in range(500):
            sample = {
                "a": rng.uniform(0.0, 1.0),
                "b": rng.uniform(0.0, 1.0),
                "c": rng.uniform(0.0, 1.0),
            }
            model.update(sample)

        typical = {"a": 0.5, "b": 0.5, "c": 0.5}
        outlier = {"a": 999.0, "b": 999.0, "c": 999.0}
        assert model.score(outlier) > model.score(typical)

    def test_save_load_round_trip(self, tmp_path, model):
        for _ in range(50):
            model.update({"a": 1.0, "b": 2.0})
        score_before = model.score({"a": 1.0, "b": 2.0})

        path = tmp_path / "hst.pkl"
        model.save(str(path))

        restored = HalfSpaceTreesModel(n_trees=10, height=6, window_size=100, seed=42)
        restored.load(str(path))
        score_after = restored.score({"a": 1.0, "b": 2.0})
        assert score_before == score_after

    def test_health_check(self, model):
        hc = model.health_check()
        assert hc["model"] == "HalfSpaceTreesModel"
        assert hc["is_online"] is True
