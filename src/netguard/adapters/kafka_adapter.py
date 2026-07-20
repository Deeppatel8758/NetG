"""Kafka consumer adapter for ingesting network flows."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime

from aiokafka import AIOKafkaConsumer

from netguard.adapters.base import NetworkFlow, SourceAdapter

logger = logging.getLogger("netguard.adapters.kafka")


class KafkaAdapter(SourceAdapter):
    """Consumes network flow JSON messages from a Kafka topic."""

    def __init__(
        self,
        brokers: list[str] | str = "localhost:9092",
        topic: str = "network-flows",
        group_id: str = "netguard-consumer",
    ) -> None:
        if isinstance(brokers, str):
            brokers = [brokers]
        self._brokers = brokers
        self._topic = topic
        self._group_id = group_id
        self._consumer: AIOKafkaConsumer | None = None

    async def start(self) -> None:
        """Create and start the Kafka consumer."""
        self._consumer = AIOKafkaConsumer(
            self._topic,
            bootstrap_servers=",".join(self._brokers),
            group_id=self._group_id,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        await self._consumer.start()
        logger.info("Kafka consumer started on topic=%s", self._topic)

    async def stream(self) -> AsyncIterator[NetworkFlow]:
        """Consume messages from Kafka, parse JSON, and yield NetworkFlow objects."""
        if self._consumer is None:
            await self.start()

        async for msg in self._consumer:
            data = msg.value
            yield NetworkFlow(
                timestamp=datetime.fromisoformat(data["timestamp"]),
                src_ip=data["src_ip"],
                dst_ip=data["dst_ip"],
                src_port=int(data["src_port"]),
                dst_port=int(data["dst_port"]),
                protocol=data.get("protocol", "TCP"),
                duration=float(data.get("duration", 0.0)),
                bytes_fwd=int(data.get("bytes_fwd", 0)),
                bytes_bwd=int(data.get("bytes_bwd", 0)),
                packets_fwd=int(data.get("packets_fwd", 0)),
                packets_bwd=int(data.get("packets_bwd", 0)),
                tcp_flags=data.get("tcp_flags", {}),
                payload_entropy=float(data.get("payload_entropy", 0.0)),
            )

    async def stop(self) -> None:
        """Close the Kafka consumer."""
        if self._consumer:
            await self._consumer.stop()
            self._consumer = None
            logger.info("Kafka consumer stopped.")

    def health_check(self) -> bool:
        """Check whether the Kafka consumer is connected."""
        return self._consumer is not None
