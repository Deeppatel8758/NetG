"""Tests for XGBoostClassifier."""

from __future__ import annotations

import numpy as np
import pytest
import xgboost as xgb

from netguard.models.feature_spec import ATTACK_CLASSES, CLASS_COUNT, FEATURE_COUNT, FEATURE_ORDER
from netguard.models.xgboost_classifier import XGBoostClassifier


def _train_tiny_booster(seed: int = 0) -> xgb.Booster:
    """Train a small multi-class booster on a synthetic 2-class-ish dataset.

    Class 0 (benign): all features near zero.
    Class 1 (port_scan): first two features large, rest zero.
    Fills the remaining classes with a smaller pool so predictions stay valid.
    """
    rng = np.random.default_rng(seed)
    per_class = 80
    X_parts = []
    y_parts = []

    # Class 0 (benign)
    X_parts.append(rng.normal(0.0, 0.05, size=(per_class, FEATURE_COUNT)))
    y_parts.append(np.zeros(per_class, dtype=int))

    # Class 1 (port_scan): distinctive first-two-features signal
    port_scan = rng.normal(0.0, 0.05, size=(per_class, FEATURE_COUNT))
    port_scan[:, 0] = 10.0 + rng.normal(0.0, 0.2, size=per_class)
    port_scan[:, 1] = 10.0 + rng.normal(0.0, 0.2, size=per_class)
    X_parts.append(port_scan)
    y_parts.append(np.ones(per_class, dtype=int))

    # A few samples per remaining class so num_class=CLASS_COUNT is valid
    for cls in range(2, CLASS_COUNT):
        block = rng.normal(0.0, 0.1, size=(20, FEATURE_COUNT))
        block[:, cls] = -5.0 + rng.normal(0.0, 0.2, size=20)
        X_parts.append(block)
        y_parts.append(np.full(20, cls, dtype=int))

    X = np.vstack(X_parts).astype(np.float32)
    y = np.concatenate(y_parts)
    dtrain = xgb.DMatrix(X, label=y)
    params = {
        "objective": "multi:softprob",
        "num_class": CLASS_COUNT,
        "max_depth": 4,
        "eta": 0.3,
        "verbosity": 0,
    }
    return xgb.train(params, dtrain, num_boost_round=50)


@pytest.fixture(scope="module")
def trained_classifier() -> XGBoostClassifier:
    booster = _train_tiny_booster()
    clf = XGBoostClassifier()
    clf.set_booster(booster)
    return clf


class TestXGBoostBasics:
    def test_untrained_returns_uniform(self):
        clf = XGBoostClassifier()
        feats = {name: 0.0 for name in FEATURE_ORDER}
        s = clf.score(feats)
        # 1 - 1/8 = 0.875
        assert s == pytest.approx(1.0 - 1.0 / CLASS_COUNT, abs=1e-4)

    def test_is_not_online(self):
        assert XGBoostClassifier().is_online is False


class TestXGBoostTrained:
    def test_benign_scores_low(self, trained_classifier):
        feats = {name: 0.0 for name in FEATURE_ORDER}
        s = trained_classifier.score(feats)
        assert s < 0.3
        assert trained_classifier.last_predicted_class == "benign"

    def test_port_scan_scores_high(self, trained_classifier):
        feats = {name: 0.0 for name in FEATURE_ORDER}
        feats[FEATURE_ORDER[0]] = 10.0
        feats[FEATURE_ORDER[1]] = 10.0
        s = trained_classifier.score(feats)
        assert s > 0.6
        # And the predicted class is the attack (index 1 = port_scan in our fixture)
        assert trained_classifier.last_predicted_class == "port_scan"

    def test_predict_class_returns_tuple(self, trained_classifier):
        feats = {name: 0.0 for name in FEATURE_ORDER}
        cls_name, conf = trained_classifier.predict_class(feats)
        assert cls_name in ATTACK_CLASSES
        assert 0.0 <= conf <= 1.0

    def test_save_load_round_trip(self, trained_classifier, tmp_path):
        path = tmp_path / "xgb.json"
        trained_classifier.save(str(path))

        restored = XGBoostClassifier(model_path=str(path))
        feats = {name: 0.0 for name in FEATURE_ORDER}
        assert trained_classifier.score(feats) == pytest.approx(restored.score(feats), abs=1e-5)

    def test_save_without_booster_raises(self, tmp_path):
        clf = XGBoostClassifier()
        with pytest.raises(RuntimeError):
            clf.save(str(tmp_path / "x.json"))
