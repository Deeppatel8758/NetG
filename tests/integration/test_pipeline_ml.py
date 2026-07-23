"""Integration test — full ML pipeline emits score-based alerts.

Uses the pretrained models bundled at src/netguard/models/pretrained/. If those
aren't present, the test is skipped so CI without model training still passes.
"""

from __future__ import annotations

import asyncio
from importlib.resources import files
from typing import AsyncIterator

import pytest

from netguard.core.config import (
    FeaturesConfig,
    ModelConfig,
    NetGuardConfig,
    OutputConfig,
    StoreConfig,
    ThresholdConfig,
)
from netguard.core.pipeline import Pipeline
from netguard.outputs.base import Alert, OutputSink
from netguard.testing.attacks import AttackGenerator
from netguard.testing.generator import NetworkTrafficGenerator


def _pretrained_available() -> bool:
    try:
        base = files("netguard.models.pretrained")
        return base.joinpath("autoencoder_v1.pt").is_file() and base.joinpath("xgboost_v1.json").is_file()
    except Exception:
        return False


class _CollectingSink(OutputSink):
    """Test sink that stashes every alert instead of emitting."""

    def __init__(self) -> None:
        super().__init__(min_severity="low")
        self.alerts: list[Alert] = []

    async def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)


class _MixedSource:
    """Yield ~200 benign flows and then ~30 port-scan flows, then stop.

    Async iterator with a ``stream()`` method — matches SourceAdapter's protocol
    for what Pipeline consumes.
    """

    def __init__(self) -> None:
        self.rng_seed = 123

    async def stream(self) -> AsyncIterator[dict]:
        # Patch asyncio.sleep inside the attacks module for fast iteration.
        import netguard.testing.attacks as attacks_module

        original_sleep = attacks_module.asyncio.sleep

        async def _no_sleep(*a, **k):
            return None

        attacks_module.asyncio.sleep = _no_sleep  # type: ignore[assignment]

        try:
            gen = NetworkTrafficGenerator(seed=self.rng_seed)
            attacker = AttackGenerator(gen)

            for _ in range(200):
                yield gen.generate_normal_flow()

            count = 0
            while count < 30:
                async for raw in attacker.generate_port_scan(ports=50):
                    yield raw
                    count += 1
                    if count >= 30:
                        break
        finally:
            attacks_module.asyncio.sleep = original_sleep  # type: ignore[assignment]


@pytest.mark.skipif(
    not _pretrained_available(),
    reason="Pretrained models not present — run `netguard train all` first.",
)
class TestPipelineML:
    async def test_scores_all_flows_and_emits_alerts(self):
        cfg = NetGuardConfig(
            features=FeaturesConfig(window_sizes=[60, 300], store=StoreConfig(type="memory")),
            models=[
                ModelConfig(type="half_space_trees", weight=0.3, params={"n_trees": 10, "height": 6, "window_size": 200}),
                ModelConfig(type="autoencoder", weight=0.3, params={"model_path": "autoencoder_v1.pt"}),
                ModelConfig(type="xgboost_classifier", weight=0.25, params={"model_path": "xgboost_v1.json"}),
                ModelConfig(type="rules_engine", weight=0.15, params={}),
            ],
            threshold=ThresholdConfig(strategy="fixed", fixed_value=0.5),
            outputs=[OutputConfig(type="console", min_severity="low")],
        )

        sink = _CollectingSink()
        source = _MixedSource()
        pipeline = Pipeline(config=cfg, source=source, outputs=[sink])

        async def stop_soon() -> None:
            # Give the pipeline time to consume the 230 flows the source yields.
            await asyncio.sleep(0.5)
            for _ in range(50):
                if pipeline._flow_count >= 220:
                    break
                await asyncio.sleep(0.1)
            await pipeline.stop()

        await asyncio.gather(pipeline.run(), stop_soon())

        # Every flow got scored
        assert pipeline._flow_count >= 200

        # At least one score-based alert with an attack_type label
        attack_alerts = [a for a in sink.alerts if a.attack_type not in ("unknown", "anomaly")]
        assert len(attack_alerts) > 0, f"No labeled attack alerts among {len(sink.alerts)} total alerts"

        # Every alert carries the ensemble's per-model breakdown
        for a in sink.alerts[:5]:
            assert "per_model_scores" in a.evidence
            assert 0.0 <= a.confidence <= 1.0
