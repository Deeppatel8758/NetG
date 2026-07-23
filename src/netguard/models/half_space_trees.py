"""Half-Space Trees anomaly detector (online, unsupervised).

Wraps river.anomaly.HalfSpaceTrees. HST scores each sample in [0, 1] where
higher = more anomalous, and learns incrementally with no labels required.
"""

from __future__ import annotations

import pickle
from pathlib import Path

from river import anomaly

from netguard.models.base import AnomalyModel


class HalfSpaceTreesModel(AnomalyModel):
    """River Half-Space Trees, wrapped as an AnomalyModel."""

    def __init__(
        self,
        n_trees: int = 30,
        height: int = 8,
        window_size: int = 1000,
        seed: int = 42,
    ) -> None:
        self._hst = anomaly.HalfSpaceTrees(
            n_trees=n_trees,
            height=height,
            window_size=window_size,
            seed=seed,
        )

    @property
    def is_online(self) -> bool:
        return True

    def score(self, features: dict) -> float:
        raw = self._hst.score_one(features)
        # River can return values slightly outside [0,1] under some feature dists;
        # clamp defensively so ensemble weights don't break.
        return float(min(1.0, max(0.0, raw)))

    def update(self, features: dict, label: float | None = None) -> None:
        self._hst.learn_one(features)

    def save(self, path: str) -> None:
        Path(path).write_bytes(pickle.dumps(self._hst))

    def load(self, path: str) -> None:
        self._hst = pickle.loads(Path(path).read_bytes())
