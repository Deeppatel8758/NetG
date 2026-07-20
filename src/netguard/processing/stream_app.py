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

logger = logging.getLogger(__name__)


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

    # Define topics
    raw_flows_topic = app.topic("raw-flows", value_type=dict)
    alerts_topic = app.topic("alerts", value_type=dict)  # noqa: F841

    @app.agent(raw_flows_topic)
    async def process_flows(stream):
        """Main processing agent -- consumes raw flows and detects anomalies."""
        flow_count = 0
        async for event in stream:
            flow_count += 1

            try:
                flow = NetworkFlow.from_dict(event)
            except Exception as e:
                logger.warning(f"Failed to parse flow: {e}")
                continue

            features = await extractor.extract(flow)

            if flow_count % 1000 == 0:
                logger.info("Processed %d flows | %d features/flow", flow_count, len(features))

            # TODO Phase 3: Score with models
            # TODO Phase 4: Check threshold, generate alerts

    @app.timer(interval=60.0)
    async def log_stats():
        """Log pipeline statistics every minute."""
        logger.info("Pipeline heartbeat -- stream processing active")

    return app


# Entry point for running with: faust -A netguard.processing.stream_app worker
app = create_app()
