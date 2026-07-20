"""Pipeline orchestration for the detection loop."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from netguard.adapters.base import NetworkFlow, SourceAdapter
from netguard.adapters.memory_adapter import MemoryAdapter
from netguard.core.config import NetGuardConfig
from netguard.features.extract import FeatureExtractor
from netguard.models.base import AnomalyModel
from netguard.outputs.base import Alert, OutputSink
from netguard.outputs.console import ConsoleOutput
from netguard.testing.generator import NetworkTrafficGenerator

logger = logging.getLogger("netguard.pipeline")


class Pipeline:
    """Orchestrates the flow: source -> features -> scoring -> threshold -> output."""

    def __init__(
        self,
        config: NetGuardConfig,
        source: Any | None = None,
        models: list[tuple[AnomalyModel, float]] | None = None,
        outputs: list[OutputSink] | None = None,
    ) -> None:
        self.config = config
        self._source = source or self._build_source()
        self._models = models or []
        self._outputs = outputs or self._build_outputs()
        self._extractor = FeatureExtractor.from_config(config.features)
        self._running = False
        self._flow_count = 0
        self._alert_count = 0
        self._start_time = 0.0

    def _build_source(self) -> SourceAdapter:
        if self.config.source.type == "memory":
            gen = NetworkTrafficGenerator()
            return MemoryAdapter(generator=gen, rate=self.config.source.memory.rate)
        # Kafka and other adapters require their dependencies
        raise ValueError(f"Source type '{self.config.source.type}' requires explicit source adapter")

    def _build_outputs(self) -> list[OutputSink]:
        sinks: list[OutputSink] = []
        for out_cfg in self.config.outputs:
            if out_cfg.type == "console":
                sinks.append(ConsoleOutput(min_severity=out_cfg.min_severity))
        return sinks or [ConsoleOutput()]

    async def run(self) -> None:
        """Main loop: read from source, extract features, score, threshold, alert."""
        self._running = True
        self._start_time = time.time()
        logger.info("Pipeline running — consuming network flows...")

        async for raw in self._source.stream():
            if not self._running:
                break

            self._flow_count += 1

            flow = NetworkFlow.from_dict(raw) if isinstance(raw, dict) else raw
            features = await self._extractor.extract(flow)

            # Log throughput every 500 flows
            if self._flow_count % 500 == 0:
                elapsed = time.time() - self._start_time
                rate = self._flow_count / elapsed if elapsed > 0 else 0
                logger.info(
                    "Processed %d flows (%.1f flows/sec) | %d alerts | %d features/flow",
                    self._flow_count, rate, self._alert_count, len(features),
                )

            # TODO Phase 3: score `features` with ML models, apply threshold
            # For now, keep the label-based demo alerting so the pipeline still emits.
            if isinstance(raw, dict) and raw.get("label") == "malicious":
                self._alert_count += 1
                alert = Alert(
                    id=f"alert_{self._alert_count:06d}",
                    timestamp=raw.get("timestamp", time.time()),
                    severity="high",
                    attack_type=raw.get("attack_type", "unknown"),
                    confidence=0.85,
                    src_ip=raw.get("src_ip", ""),
                    dst_ip=raw.get("dst_ip", ""),
                    src_port=raw.get("src_port", 0),
                    dst_port=raw.get("dst_port", 0),
                    description=f"Detected {raw.get('attack_type', 'anomaly')} from {raw.get('src_ip')}",
                    evidence={"label": raw.get("label"), "attack_type": raw.get("attack_type")},
                    recommended_action="Investigate source host",
                )
                for output in self._outputs:
                    await output.emit(alert)

    async def stop(self) -> None:
        """Signal the pipeline to stop."""
        logger.info("Pipeline stopping...")
        self._running = False
        await self._extractor.close()
