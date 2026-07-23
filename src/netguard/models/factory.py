"""Model factory — turn a ModelConfig into a concrete AnomalyModel.

Bundled model files (autoencoder, xgboost) live under
``src/netguard/models/pretrained/`` and are resolved via importlib.resources.
Absolute paths in ``params.model_path`` bypass this resolution.
"""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path

from netguard.core.config import ModelConfig
from netguard.models.autoencoder import AutoencoderModel
from netguard.models.base import AnomalyModel
from netguard.models.half_space_trees import HalfSpaceTreesModel
from netguard.models.rules_engine import RulesEngineModel
from netguard.models.xgboost_classifier import XGBoostClassifier

_PRETRAINED_PKG = "netguard.models.pretrained"


def _resolve_model_path(raw: str | None) -> str | None:
    """Resolve a model_path against the bundled pretrained package if it's a bare name.

    Rules:
    - None → None (caller decides).
    - Absolute path or path containing a slash → used as-is.
    - Bare filename → resolved to netguard.models.pretrained/<name>.
    """
    if raw is None:
        return None
    p = Path(raw)
    if p.is_absolute() or len(p.parts) > 1:
        return str(p)
    # Bare filename → look it up in the bundled package.
    resource = files(_PRETRAINED_PKG).joinpath(raw)
    return str(resource)


def build_model(cfg: ModelConfig) -> AnomalyModel:
    """Instantiate an AnomalyModel from a ModelConfig."""
    params = dict(cfg.params or {})
    model_type = cfg.type

    if model_type == "half_space_trees":
        return HalfSpaceTreesModel(
            n_trees=int(params.get("n_trees", 30)),
            height=int(params.get("height", 8)),
            window_size=int(params.get("window_size", 1000)),
            seed=int(params.get("seed", 42)),
        )

    if model_type == "autoencoder":
        return AutoencoderModel(model_path=_resolve_model_path(params.get("model_path")))

    if model_type == "xgboost_classifier":
        return XGBoostClassifier(model_path=_resolve_model_path(params.get("model_path")))

    if model_type == "rules_engine":
        return RulesEngineModel()

    raise ValueError(f"Unknown model type: {model_type!r}")
