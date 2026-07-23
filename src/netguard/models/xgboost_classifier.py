"""XGBoost multi-class attack-type classifier.

Predicts P(class) over ATTACK_CLASSES (benign + 7 attack types).
Anomaly score = 1 - P(benign); winning class exposed via `last_predicted_class`
so the ensemble can label the alert's attack_type.
"""

from __future__ import annotations

import numpy as np
import xgboost as xgb

from netguard.models.base import AnomalyModel
from netguard.models.feature_spec import ATTACK_CLASSES, CLASS_COUNT, to_vector


class XGBoostClassifier(AnomalyModel):
    """XGBoost multi-class classifier wrapped as an AnomalyModel."""

    def __init__(self, model_path: str | None = None) -> None:
        self._booster: xgb.Booster | None = None
        self.last_predicted_class: str | None = None
        self.last_class_confidence: float = 0.0
        if model_path is not None:
            self.load(model_path)

    @property
    def is_online(self) -> bool:
        return False

    def _predict(self, features: dict) -> np.ndarray:
        if self._booster is None:
            # Uniform prior over classes when no model is loaded — anomaly score
            # will then be 1 - 1/CLASS_COUNT, which is a sensible "unknown" signal.
            return np.full(CLASS_COUNT, 1.0 / CLASS_COUNT, dtype=np.float32)
        vec = to_vector(features).reshape(1, -1)
        dmat = xgb.DMatrix(vec)
        probs = self._booster.predict(dmat)[0]
        return np.asarray(probs, dtype=np.float32)

    def score(self, features: dict) -> float:
        probs = self._predict(features)
        idx = int(np.argmax(probs))
        self.last_predicted_class = ATTACK_CLASSES[idx]
        self.last_class_confidence = float(probs[idx])
        # Anomaly = 1 - P(benign).
        return float(max(0.0, min(1.0, 1.0 - probs[0])))

    def predict_class(self, features: dict) -> tuple[str, float]:
        """Return (class_name, confidence) for the top prediction."""
        probs = self._predict(features)
        idx = int(np.argmax(probs))
        return ATTACK_CLASSES[idx], float(probs[idx])

    def set_booster(self, booster: xgb.Booster) -> None:
        self._booster = booster

    def save(self, path: str) -> None:
        if self._booster is None:
            raise RuntimeError("No booster to save — train or load one first.")
        self._booster.save_model(path)

    def load(self, path: str) -> None:
        self._booster = xgb.Booster()
        self._booster.load_model(path)
