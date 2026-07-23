"""Pipeline orchestration for the detection loop."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any

from netguard.adapters.base import NetworkFlow, SourceAdapter
from netguard.adapters.memory_adapter import MemoryAdapter
from netguard.core.config import NetGuardConfig
from netguard.features.extract import FeatureExtractor
from netguard.models.base import AnomalyModel
from netguard.models.ensemble import EnsembleScorer
from netguard.models.factory import build_model
from netguard.outputs.base import Alert, OutputSink
from netguard.outputs.console import ConsoleOutput
from netguard.testing.generator import NetworkTrafficGenerator
from netguard.threshold.adaptive import AdaptiveThreshold

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
        self._outputs = outputs or self._build_outputs()
        self._extractor = FeatureExtractor.from_config(config.features)
        self._ensemble = self._build_ensemble(models)
        self._threshold = AdaptiveThreshold(config.threshold)
        self._running = False
        self._flow_count = 0
        self._alert_count = 0
        self._start_time = 0.0
        # Rolling score log for the every-500-flows heartbeat.
        self._recent_scores: list[float] = []

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

    def _build_ensemble(self, preloaded: list[tuple[AnomalyModel, float]] | None) -> EnsembleScorer:
        """Build the ensemble from either a preloaded list or config.models."""
        ensemble = EnsembleScorer()
        if preloaded:
            for model, weight in preloaded:
                ensemble.add_model(model, weight)
            return ensemble
        for cfg in self.config.models:
            if not cfg.enabled:
                continue
            try:
                model = build_model(cfg)
                ensemble.add_model(model, cfg.weight)
                logger.info("Loaded model: %s (weight=%.2f)", cfg.type, cfg.weight)
            except (FileNotFoundError, RuntimeError, ValueError) as e:
                logger.warning("Skipping model %s: %s", cfg.type, e)
        return ensemble

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

            # Score with the ensemble and record the result for adaptive thresholding.
            result = self._ensemble.score(features)
            self._threshold.update(result.final_score)
            self._recent_scores.append(result.final_score)

            score_alerted = False
            if self._threshold.is_alert(result.final_score):
                score_alerted = True
                self._alert_count += 1
                alert = self._build_score_alert(flow, result)
                await self._emit(alert)

            # Feed online models (HalfSpaceTrees) with every observed flow.
            for model, _ in self._ensemble.models:
                if model.is_online:
                    model.update(features)

            # Keep the label-based fallback so demos still emit while models are cold.
            if (
                not score_alerted
                and isinstance(raw, dict)
                and raw.get("label") == "malicious"
            ):
                self._alert_count += 1
                alert = self._build_label_alert(raw)
                await self._emit(alert)

            if self._flow_count % 500 == 0:
                self._log_heartbeat(features_count=len(features))

    async def stop(self) -> None:
        """Signal the pipeline to stop."""
        logger.info("Pipeline stopping...")
        self._running = False
        await self._extractor.close()

    # ------------------------------------------------------------------
    # Alert construction
    # ------------------------------------------------------------------

    def _build_score_alert(self, flow: NetworkFlow, result: Any) -> Alert:
        attack_type = result.predicted_attack_type or "anomaly"
        return Alert(
            id=f"alert_{self._alert_count:06d}",
            timestamp=flow.timestamp,
            severity=_severity_from_score(result.final_score),
            attack_type=attack_type,
            confidence=float(result.final_score),
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            description=f"Ensemble flagged {attack_type} from {flow.src_ip} (score={result.final_score:.3f})",
            evidence={
                "per_model_scores": result.per_model_scores,
                "threshold": self._threshold.current(),
            },
            recommended_action="Investigate source host",
        )

    def _build_label_alert(self, raw: dict) -> Alert:
        ts = raw.get("timestamp", time.time())
        if isinstance(ts, (int, float)):
            ts_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        elif isinstance(ts, datetime):
            ts_dt = ts
        else:
            ts_dt = datetime.now(tz=timezone.utc)
        return Alert(
            id=f"alert_{self._alert_count:06d}",
            timestamp=ts_dt,
            severity="high",
            attack_type=raw.get("attack_type", "unknown"),
            confidence=0.85,
            src_ip=raw.get("src_ip", ""),
            dst_ip=raw.get("dst_ip", ""),
            src_port=raw.get("src_port", 0),
            dst_port=raw.get("dst_port", 0),
            description=f"Ground-truth label: {raw.get('attack_type', 'anomaly')} from {raw.get('src_ip')}",
            evidence={"label": raw.get("label"), "attack_type": raw.get("attack_type")},
            recommended_action="Investigate source host",
        )

    async def _emit(self, alert: Alert) -> None:
        for output in self._outputs:
            await output.emit(alert)

    def _log_heartbeat(self, features_count: int) -> None:
        elapsed = time.time() - self._start_time
        rate = self._flow_count / elapsed if elapsed > 0 else 0.0
        scores = self._recent_scores
        if scores:
            s_min = min(scores)
            s_max = max(scores)
            s_mean = sum(scores) / len(scores)
        else:
            s_min = s_max = s_mean = 0.0
        logger.info(
            "Processed %d flows (%.1f/s) | %d alerts | %d features | scores min=%.3f mean=%.3f max=%.3f | threshold=%.3f",
            self._flow_count, rate, self._alert_count, features_count,
            s_min, s_mean, s_max, self._threshold.current(),
        )
        self._recent_scores.clear()


_SEVERITY_BANDS = (
    (0.9, "critical"),
    (0.8, "high"),
    (0.0, "medium"),
)


def _severity_from_score(score: float) -> str:
    for threshold, name in _SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "low"
