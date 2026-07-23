"""Train the NetGuard XGBoost attack-type classifier on synthetic traffic.

Usage:
    python scripts/train_xgboost.py --benign 20000 --attack 3000 \
        --out src/netguard/models/pretrained/xgboost_v1.json

For each of the 7 attack classes we sample ``--attack`` flows from that
attack's generator. Labels come from ATTACK_CLASSES.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Sequence

import numpy as np
import xgboost as xgb

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netguard.adapters.base import NetworkFlow  # noqa: E402
from netguard.features.extract import FeatureExtractor  # noqa: E402
from netguard.features.store import MemoryStore  # noqa: E402
from netguard.models.feature_spec import ATTACK_CLASSES, CLASS_COUNT, to_vector  # noqa: E402
from netguard.testing.attacks import AttackGenerator  # noqa: E402
from netguard.testing.generator import NetworkTrafficGenerator  # noqa: E402


ATTACK_METHOD_MAP = {
    "port_scan": "generate_port_scan",
    "syn_flood": "generate_syn_flood",
    "brute_force": "generate_brute_force",
    "c2_beacon": "generate_c2_beacon",
    "lateral_movement": "generate_lateral_movement",
    "dns_tunnel": "generate_dns_tunnel",
    "exfiltration": "generate_exfiltration",
}


async def _no_sleep(*args, **kwargs) -> None:
    """Drop-in replacement for asyncio.sleep during training data collection.

    Attack generators use asyncio.sleep to model realistic inter-flow delays
    (up to 30s in some cases). Bypassing those makes bulk data collection
    a few hundred flows/sec instead of one every few seconds.
    """
    return None


async def _collect_dataset(benign: int, attack: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Return (X, y) vectors for benign + each attack class."""
    import asyncio as _asyncio_mod

    from netguard.testing import attacks as attacks_module

    gen = NetworkTrafficGenerator(seed=seed)
    attacker = AttackGenerator(gen)
    ext = FeatureExtractor(store=MemoryStore(), windows_sec=(60, 300))

    xs: list[np.ndarray] = []
    ys: list[int] = []

    print(f"  collecting {benign} benign flows...")
    for _ in range(benign):
        raw = gen.generate_normal_flow()
        flow = NetworkFlow.from_dict(raw)
        features = await ext.extract(flow)
        xs.append(to_vector(features))
        ys.append(0)  # ATTACK_CLASSES[0] == "benign"

    # Patch asyncio.sleep inside the attacks module so generators yield at wire speed.
    original_sleep = attacks_module.asyncio.sleep
    attacks_module.asyncio.sleep = _no_sleep  # type: ignore[assignment]
    try:
        for cls_idx in range(1, CLASS_COUNT):
            cls_name = ATTACK_CLASSES[cls_idx]
            method_name = ATTACK_METHOD_MAP[cls_name]
            print(f"  collecting {attack} flows for class '{cls_name}'...")
            count = 0
            # Some attack generators loop over a fixed set of ports/attempts;
            # if that's less than `attack`, restart with fresh IPs.
            while count < attack:
                async for raw in getattr(attacker, method_name)():
                    flow = NetworkFlow.from_dict(raw)
                    features = await ext.extract(flow)
                    xs.append(to_vector(features))
                    ys.append(cls_idx)
                    count += 1
                    if count >= attack:
                        break
    finally:
        attacks_module.asyncio.sleep = original_sleep  # type: ignore[assignment]

    return np.stack(xs, axis=0), np.asarray(ys, dtype=np.int32)


def main(
    benign: int = 20_000,
    attack: int = 3_000,
    seed: int = 42,
    n_estimators: int = 100,
    max_depth: int = 6,
    out: str | None = None,
) -> Path:
    """Train and save the XGBoost booster. Returns the output path."""
    out_path = Path(
        out
        or Path(__file__).resolve().parents[1]
        / "src"
        / "netguard"
        / "models"
        / "pretrained"
        / "xgboost_v1.json"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print("Collecting training data...")
    X, y = asyncio.run(_collect_dataset(benign=benign, attack=attack, seed=seed))
    print(f"  dataset: X={X.shape}, y=distribution {np.bincount(y, minlength=CLASS_COUNT).tolist()}")

    # Shuffle then split 90/10 for eval
    rng = np.random.default_rng(seed)
    perm = rng.permutation(X.shape[0])
    X, y = X[perm], y[perm]
    split = int(X.shape[0] * 0.9)
    X_train, X_eval = X[:split], X[split:]
    y_train, y_eval = y[:split], y[split:]

    dtrain = xgb.DMatrix(X_train, label=y_train)
    deval = xgb.DMatrix(X_eval, label=y_eval)
    params = {
        "objective": "multi:softprob",
        "num_class": CLASS_COUNT,
        "max_depth": max_depth,
        "eta": 0.1,
        "eval_metric": "mlogloss",
        "tree_method": "hist",
        "verbosity": 1,
    }

    print(f"Training XGBoost ({n_estimators} rounds, depth={max_depth})...")
    booster = xgb.train(
        params,
        dtrain,
        num_boost_round=n_estimators,
        evals=[(deval, "eval")],
        verbose_eval=20,
    )

    booster.save_model(str(out_path))
    size_kb = out_path.stat().st_size / 1024
    print(f"Saved XGBoost model to {out_path} ({size_kb:.1f} KB)")
    return out_path


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train the NetGuard XGBoost classifier.")
    p.add_argument("--benign", type=int, default=20_000)
    p.add_argument("--attack", type=int, default=3_000, help="Flows per attack class")
    p.add_argument("--n-estimators", type=int, default=100)
    p.add_argument("--max-depth", type=int, default=6)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", type=str, default=None)
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    main(
        benign=args.benign,
        attack=args.attack,
        seed=args.seed,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        out=args.out,
    )
