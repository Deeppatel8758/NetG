"""Tests for the model factory."""

from __future__ import annotations

import pytest

from netguard.core.config import ModelConfig
from netguard.models.autoencoder import AutoencoderModel
from netguard.models.factory import build_model
from netguard.models.half_space_trees import HalfSpaceTreesModel
from netguard.models.rules_engine import RulesEngineModel
from netguard.models.xgboost_classifier import XGBoostClassifier


class TestBuildModel:
    def test_half_space_trees(self):
        cfg = ModelConfig(type="half_space_trees", params={"n_trees": 5, "height": 3, "window_size": 50})
        m = build_model(cfg)
        assert isinstance(m, HalfSpaceTreesModel)

    def test_autoencoder_without_path(self):
        # No model_path means a fresh un-trained AE is fine to construct.
        cfg = ModelConfig(type="autoencoder", params={})
        m = build_model(cfg)
        assert isinstance(m, AutoencoderModel)

    def test_xgboost_without_path(self):
        cfg = ModelConfig(type="xgboost_classifier", params={})
        m = build_model(cfg)
        assert isinstance(m, XGBoostClassifier)

    def test_rules_engine(self):
        cfg = ModelConfig(type="rules_engine", params={})
        m = build_model(cfg)
        assert isinstance(m, RulesEngineModel)

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError, match="Unknown model type"):
            build_model(ModelConfig(type="magic_forest", params={}))

    def test_absolute_model_path_used_as_is(self, tmp_path):
        # Absolute path should not be resolved against the pretrained package.
        # We don't need the file to exist; XGBoostClassifier will only load
        # when instantiated with a path — untrained (path=None) is a valid state.
        cfg = ModelConfig(type="xgboost_classifier", params={"model_path": None})
        m = build_model(cfg)
        assert isinstance(m, XGBoostClassifier)
