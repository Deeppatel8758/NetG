"""
NetGuard Stream Processing Application

This is the main Faust app that:
1. Consumes raw flows from Kafka
2. Parses and validates them
3. Extracts features
4. Scores with ML models
5. Checks thresholds
6. Produces alerts
"""

from __future__ import annotations

import logging

import faust

from netguard.adapters.base import NetworkFlow
from netguard.core.config import NetGuardConfig
from netguard.features.extract import FeatureExtractor
from netguard.models.ensemble import EnsembleScorer
from netguard.models.factory import build_model
from netguard.threshold.adaptive import AdaptiveThreshold

logger = logging.getLogger(__name__)


def _build_ensemble(cfg: NetGuardConfig) -> EnsembleScorer:
    ensemble = EnsembleScorer()
    for m_cfg in cfg.models:
        if not m_cfg.enabled:
            continue
        try:
            ensemble.add_model(build_model(m_cfg), m_cfg.weight)
            logger.info("Loaded model: %s (weight=%.2f)", m_cfg.type, m_cfg.weight)
        except (FileNotFoundError, RuntimeError, ValueError) as e:
            logger.warning("Skipping model %s: %s", m_cfg.type, e)
    return ensemble


def create_app(kafka_brokers: str = "localhost:9092", config: NetGuardConfig | None = None) -> faust.App:
    """Create and configure the Faust streaming app."""
    app = faust.App(
        "netguard",
        broker=f"kafka://{kafka_brokers}",
        value_serializer="json",
        logging_config=None,
    )

    cfg = config or NetGuardConfig()
    extractor = FeatureExtractor.from_config(cfg.features)
    ensemble = _build_ensemble(cfg)
    threshold = AdaptiveThreshold(cfg.threshold)

    # Define topics
    raw_flows_topic = app.topic("raw-flows", value_type=dict)
    alerts_topic = app.topic("alerts", value_type=dict)

    @app.agent(raw_flows_topic)
    async def process_flows(stream):
        """Main processing agent -- consumes raw flows and detects anomalies."""
        flow_count = 0
        alert_count = 0
        async for event in stream:
            flow_count += 1

            try:
                flow = NetworkFlow.from_dict(event)
            except Exception as e:
                logger.warning(f"Failed to parse flow: {e}")
                continue

            features = await extractor.extract(flow)
            result = ensemble.score(features)
            threshold.update(result.final_score)

            if threshold.is_alert(result.final_score):
                alert_count += 1
                await alerts_topic.send(value={
                    "id": f"alert_{alert_count:06d}",
                    "src_ip": flow.src_ip,
                    "dst_ip": flow.dst_ip,
                    "attack_type": result.predicted_attack_type or "anomaly",
                    "confidence": result.final_score,
                    "per_model_scores": result.per_model_scores,
                    "threshold": threshold.current(),
                })

            for model, _ in ensemble.models:
                if model.is_online:
                    model.update(features)

            if flow_count % 1000 == 0:
                logger.info(
                    "Processed %d flows | %d alerts | threshold=%.3f",
                    flow_count, alert_count, threshold.current(),
                )

    @app.timer(interval=60.0)
    async def log_stats():
        """Log pipeline statistics every minute."""
        logger.info("Pipeline heartbeat -- stream processing active")

    return app


# Entry point for running with: faust -A netguard.processing.stream_app worker
app = create_app()
