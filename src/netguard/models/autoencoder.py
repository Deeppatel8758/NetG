"""Autoencoder anomaly detector (PyTorch).

Encoder/decoder over the fixed FEATURE_ORDER vector. Trained on benign flows;
reconstruction error normalizes to an anomaly score in [0, 1].

The saved bundle carries the model weights, the fitted StandardScaler stats,
and calibration percentiles so inference is a single file load.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import torch
import torch.nn as nn

from netguard.models.base import AnomalyModel
from netguard.models.feature_spec import FEATURE_COUNT, to_vector

torch.set_num_threads(1)


@dataclass
class ScalerStats:
    """Just the fields we need from a fitted sklearn StandardScaler."""

    mean: np.ndarray
    scale: np.ndarray

    def transform(self, x: np.ndarray) -> np.ndarray:
        return (x - self.mean) / np.where(self.scale == 0.0, 1.0, self.scale)

    @classmethod
    def from_sklearn(cls, sk_scaler: Any) -> ScalerStats:
        return cls(mean=np.asarray(sk_scaler.mean_, dtype=np.float32),
                   scale=np.asarray(sk_scaler.scale_, dtype=np.float32))


class _AENet(nn.Module):
    """Symmetric MLP autoencoder: 41 → 32 → 16 → 8 → 16 → 32 → 41."""

    def __init__(self, dim: int = FEATURE_COUNT) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(dim, 32), nn.ReLU(),
            nn.Linear(32, 16), nn.ReLU(),
            nn.Linear(16, 8), nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16), nn.ReLU(),
            nn.Linear(16, 32), nn.ReLU(),
            nn.Linear(32, dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decoder(self.encoder(x))


class AutoencoderModel(AnomalyModel):
    """PyTorch autoencoder scoring via reconstruction error."""

    def __init__(self, model_path: str | None = None) -> None:
        self._net = _AENet()
        self._net.eval()
        # Calibration: err at these levels on the training set.
        # Defaults keep score returning a well-defined value on an untrained bundle.
        self._scaler: ScalerStats | None = None
        self._err_p50 = 0.0
        self._err_p99 = 1.0
        if model_path is not None:
            self.load(model_path)

    @property
    def is_online(self) -> bool:
        return False

    def _reconstruction_error(self, vec: np.ndarray) -> float:
        if self._scaler is not None:
            vec = self._scaler.transform(vec)
        tensor = torch.from_numpy(vec.astype(np.float32)).unsqueeze(0)
        with torch.inference_mode():
            recon = self._net(tensor).squeeze(0).numpy()
        # Mean squared error over features.
        return float(np.mean((vec - recon) ** 2))

    def score(self, features: dict) -> float:
        vec = to_vector(features)
        err = self._reconstruction_error(vec)
        # Normalize so p99 of benign training maps to ~1.0.
        # Clamp; scores above p99 are still "very anomalous" but capped for ensemble use.
        if self._err_p99 <= 0.0:
            return 0.0
        return float(min(1.0, max(0.0, err / self._err_p99)))

    def fit_calibration(self, errors: np.ndarray) -> None:
        """Record the p50/p99 of a set of reconstruction errors (training set)."""
        self._err_p50 = float(np.percentile(errors, 50))
        self._err_p99 = float(np.percentile(errors, 99))

    def set_scaler(self, scaler: ScalerStats) -> None:
        self._scaler = scaler

    @property
    def net(self) -> _AENet:
        return self._net

    def save(self, path: str) -> None:
        bundle = {
            "state_dict": self._net.state_dict(),
            "scaler_mean": None if self._scaler is None else self._scaler.mean,
            "scaler_scale": None if self._scaler is None else self._scaler.scale,
            "err_p50": self._err_p50,
            "err_p99": self._err_p99,
            "feature_count": FEATURE_COUNT,
        }
        torch.save(bundle, path)

    def load(self, path: str) -> None:
        bundle = torch.load(path, map_location="cpu", weights_only=False)
        if bundle.get("feature_count", FEATURE_COUNT) != FEATURE_COUNT:
            raise ValueError(
                f"AutoencoderModel bundle expects {bundle['feature_count']} features, "
                f"but current FEATURE_ORDER has {FEATURE_COUNT}. Retrain the model."
            )
        self._net.load_state_dict(bundle["state_dict"])
        self._net.eval()
        if bundle.get("scaler_mean") is not None:
            self._scaler = ScalerStats(
                mean=np.asarray(bundle["scaler_mean"], dtype=np.float32),
                scale=np.asarray(bundle["scaler_scale"], dtype=np.float32),
            )
        else:
            self._scaler = None
        self._err_p50 = float(bundle.get("err_p50", 0.0))
        self._err_p99 = float(bundle.get("err_p99", 1.0))
