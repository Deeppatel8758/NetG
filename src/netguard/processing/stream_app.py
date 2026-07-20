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

logger = logging.getLogger(__name__)


def create_app(kafka_brokers: str = "localhost:9092") -> faust.App:
    """Create and configure the Faust streaming app."""
    app = faust.App(
        "netguard",
        broker=f"kafka://{kafka_brokers}",
        value_serializer="json",
        logging_config=None,
    )

    # Define topics
    raw_flows_topic = app.topic("raw-flows", value_type=dict)
    alerts_topic = app.topic("alerts", value_type=dict)  # noqa: F841

    @app.agent(raw_flows_topic)
    async def process_flows(stream):
        """Main processing agent -- consumes raw flows and detects anomalies."""
        flow_count = 0
        async for event in stream:
            flow_count += 1

            # Parse into NetworkFlow
            try:
                flow = NetworkFlow(
                    timestamp=event.get("timestamp", 0),
                    src_ip=event.get("src_ip", ""),
                    dst_ip=event.get("dst_ip", ""),
                    src_port=event.get("src_port", 0),
                    dst_port=event.get("dst_port", 0),
                    protocol=event.get("protocol", "TCP"),
                    duration=event.get("duration", 0),
                    bytes_fwd=event.get("bytes_fwd", 0),
                    bytes_bwd=event.get("bytes_bwd", 0),
                    packets_fwd=event.get("packets_fwd", 0),
                    packets_bwd=event.get("packets_bwd", 0),
                    tcp_flags=event.get("tcp_flags", {}),
                    payload_entropy=event.get("payload_entropy", 0.0),
                )
            except Exception as e:
                logger.warning(f"Failed to parse flow: {e}")
                continue

            if flow_count % 1000 == 0:
                logger.info(f"Processed {flow_count} flows")

            # TODO Phase 2: Extract features
            # TODO Phase 3: Score with models
            # TODO Phase 4: Check threshold, generate alerts

    @app.timer(interval=60.0)
    async def log_stats():
        """Log pipeline statistics every minute."""
        logger.info("Pipeline heartbeat -- stream processing active")

    return app


# Entry point for running with: faust -A netguard.processing.stream_app worker
app = create_app()
