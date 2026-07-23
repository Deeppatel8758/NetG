"""Tests for AutoencoderModel."""

from __future__ import annotations

import numpy as np
import pytest
import torch

from netguard.models.autoencoder import AutoencoderModel, ScalerStats
from netguard.models.feature_spec import FEATURE_COUNT, FEATURE_ORDER


def _sample_features(seed: int = 0) -> dict:
    rng = np.random.default_rng(seed)
    return {name: float(rng.uniform(-1.0, 1.0)) for name in FEATURE_ORDER}


class TestAutoencoderModel:
    def test_score_in_unit_interval(self):
        m = AutoencoderModel()
        # Untrained: err_p99 defaults to 1.0, so score in [0,1]
        s = m.score(_sample_features())
        assert 0.0 <= s <= 1.0

    def test_is_not_online(self):
        assert AutoencoderModel().is_online is False

    def test_score_defaults_to_zero_when_p99_zero(self):
        m = AutoencoderModel()
        m._err_p99 = 0.0
        assert m.score(_sample_features()) == 0.0

    def test_calibration_moves_score(self):
        m = AutoencoderModel()
        # Give it a tight calibration so any error looks anomalous
        m.fit_calibration(np.array([0.001, 0.002, 0.003, 0.004, 0.005]))
        assert m._err_p99 < 1.0

    def test_out_of_distribution_scores_higher_after_training(self):
        # Train on a benign distribution, verify OOD input scores higher.
        m = AutoencoderModel()
        rng = np.random.default_rng(42)
        # Benign: values near zero
        benign_matrix = rng.normal(loc=0.0, scale=0.1, size=(200, FEATURE_COUNT)).astype(np.float32)

        # Fit a lightweight scaler
        mean = benign_matrix.mean(axis=0)
        std = benign_matrix.std(axis=0) + 1e-8
        m.set_scaler(ScalerStats(mean=mean.astype(np.float32), scale=std.astype(np.float32)))

        # Minimal training
        optimizer = torch.optim.Adam(m.net.parameters(), lr=1e-3)
        loss_fn = torch.nn.MSELoss()
        m.net.train()
        x = torch.from_numpy((benign_matrix - mean) / std)
        for _ in range(50):
            optimizer.zero_grad()
            recon = m.net(x)
            loss = loss_fn(recon, x)
            loss.backward()
            optimizer.step()
        m.net.eval()

        # Calibrate against training set
        with torch.inference_mode():
            recon = m.net(x).numpy()
        errs = np.mean(((x.numpy() - recon) ** 2), axis=1)
        m.fit_calibration(errs)

        # In-distribution sample vs. an outlier (values far from training mean)
        in_dist = {name: float(rng.normal(0.0, 0.1)) for name in FEATURE_ORDER}
        out_dist = {name: 10.0 for name in FEATURE_ORDER}
        assert m.score(out_dist) > m.score(in_dist)

    def test_save_load_round_trip(self, tmp_path):
        m = AutoencoderModel()
        mean = np.ones(FEATURE_COUNT, dtype=np.float32) * 2.0
        scale = np.ones(FEATURE_COUNT, dtype=np.float32) * 3.0
        m.set_scaler(ScalerStats(mean=mean, scale=scale))
        m.fit_calibration(np.array([0.1, 0.2, 0.3, 0.4, 0.5]))

        path = tmp_path / "ae.pt"
        m.save(str(path))

        restored = AutoencoderModel(model_path=str(path))
        assert restored._scaler is not None
        np.testing.assert_array_equal(restored._scaler.mean, mean)
        np.testing.assert_array_equal(restored._scaler.scale, scale)
        assert restored._err_p50 == pytest.approx(m._err_p50)
        assert restored._err_p99 == pytest.approx(m._err_p99)

        # Scores must match after round trip
        feats = _sample_features(seed=7)
        assert m.score(feats) == pytest.approx(restored.score(feats), abs=1e-6)

    def test_load_rejects_wrong_feature_count(self, tmp_path):
        m = AutoencoderModel()
        path = tmp_path / "ae.pt"
        # Manually save a bundle with the wrong feature count
        bundle = {
            "state_dict": m.net.state_dict(),
            "scaler_mean": None,
            "scaler_scale": None,
            "err_p50": 0.0,
            "err_p99": 1.0,
            "feature_count": FEATURE_COUNT + 5,
        }
        torch.save(bundle, path)

        with pytest.raises(ValueError, match="feature"):
            AutoencoderModel(model_path=str(path))
