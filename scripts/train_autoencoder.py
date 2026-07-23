"""Train the NetGuard autoencoder on synthetic benign traffic.

Usage:
    python scripts/train_autoencoder.py --flows 100000 --epochs 20 \
        --out src/netguard/models/pretrained/autoencoder_v1.pt
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Sequence

import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

# Make src/ importable when running the script directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from netguard.adapters.base import NetworkFlow  # noqa: E402
from netguard.features.extract import FeatureExtractor  # noqa: E402
from netguard.features.store import MemoryStore  # noqa: E402
from netguard.models.autoencoder import AutoencoderModel, ScalerStats  # noqa: E402
from netguard.models.feature_spec import FEATURE_COUNT, to_vector  # noqa: E402
from netguard.testing.generator import NetworkTrafficGenerator  # noqa: E402


async def _collect_benign_vectors(flows: int, seed: int) -> np.ndarray:
    """Drive the generator + extractor in-process and collect feature vectors."""
    gen = NetworkTrafficGenerator(seed=seed)
    ext = FeatureExtractor(store=MemoryStore(), windows_sec=(60, 300))

    vectors: list[np.ndarray] = []
    for _ in range(flows):
        raw = gen.generate_normal_flow()
        flow = NetworkFlow.from_dict(raw)
        features = await ext.extract(flow)
        vectors.append(to_vector(features))

    return np.stack(vectors, axis=0)


def _train_loop(
    model: AutoencoderModel,
    x_train: np.ndarray,
    epochs: int,
    batch_size: int,
    lr: float,
) -> None:
    x_tensor = torch.from_numpy(x_train.astype(np.float32))
    optimizer = torch.optim.Adam(model.net.parameters(), lr=lr)
    loss_fn = nn.MSELoss()

    model.net.train()
    n = x_tensor.size(0)
    for epoch in range(epochs):
        # Shuffle indices per epoch
        perm = torch.randperm(n)
        total_loss = 0.0
        for i in range(0, n, batch_size):
            idx = perm[i : i + batch_size]
            batch = x_tensor[idx]
            optimizer.zero_grad()
            recon = model.net(batch)
            loss = loss_fn(recon, batch)
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item()) * batch.size(0)
        print(f"  epoch {epoch + 1}/{epochs}  train_loss={total_loss / n:.6f}")
    model.net.eval()


def main(
    flows: int = 100_000,
    epochs: int = 20,
    batch_size: int = 256,
    lr: float = 1e-3,
    seed: int = 42,
    out: str | None = None,
) -> Path:
    """Train and save an autoencoder. Returns the output path."""
    out_path = Path(
        out
        or Path(__file__).resolve().parents[1]
        / "src"
        / "netguard"
        / "models"
        / "pretrained"
        / "autoencoder_v1.pt"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Collecting {flows} benign flows...")
    x = asyncio.run(_collect_benign_vectors(flows, seed))
    print(f"  collected {x.shape[0]} vectors of dim {x.shape[1]}")

    # 90/10 train/holdout for calibration
    rng = np.random.default_rng(seed)
    perm = rng.permutation(x.shape[0])
    split = int(x.shape[0] * 0.9)
    train_idx, hold_idx = perm[:split], perm[split:]

    scaler = StandardScaler()
    scaler.fit(x[train_idx])
    x_train = scaler.transform(x[train_idx])
    x_hold = scaler.transform(x[hold_idx])

    model = AutoencoderModel()
    if FEATURE_COUNT != x.shape[1]:
        raise RuntimeError(f"Feature count mismatch: spec={FEATURE_COUNT}, data={x.shape[1]}")
    model.set_scaler(ScalerStats.from_sklearn(scaler))

    print(f"Training AE for {epochs} epochs (batch={batch_size}, lr={lr})...")
    _train_loop(model, x_train, epochs=epochs, batch_size=batch_size, lr=lr)

    # Calibration on held-out benign
    with torch.inference_mode():
        recon = model.net(torch.from_numpy(x_hold.astype(np.float32))).numpy()
    errors = np.mean((x_hold - recon) ** 2, axis=1)
    model.fit_calibration(errors)
    print(f"  calibration: err_p50={model._err_p50:.6f}  err_p99={model._err_p99:.6f}")

    model.save(str(out_path))
    print(f"Saved autoencoder to {out_path} ({out_path.stat().st_size / 1024:.1f} KB)")
    return out_path


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train the NetGuard autoencoder.")
    p.add_argument("--flows", type=int, default=100_000)
    p.add_argument("--epochs", type=int, default=20)
    p.add_argument("--batch-size", type=int, default=256)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", type=str, default=None)
    return p.parse_args(argv)


if __name__ == "__main__":
    args = _parse_args()
    main(
        flows=args.flows,
        epochs=args.epochs,
        batch_size=args.batch_size,
        lr=args.lr,
        seed=args.seed,
        out=args.out,
    )
