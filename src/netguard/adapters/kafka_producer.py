"""Kafka producer utility for emitting network flow events."""

from __future__ import annotations

import json

from aiokafka import AIOKafkaProducer


class KafkaFlowProducer:
    """Produces network flow events to a Kafka topic."""

    def __init__(self, brokers: str = "localhost:9092", topic: str = "raw-flows"):
        self.brokers = brokers
        self.topic = topic
        self._producer: AIOKafkaProducer | None = None

    async def _ensure_connected(self):
        if self._producer is None:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.brokers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                compression_type="lz4",
                linger_ms=10,
                batch_size=16384,
            )
            await self._producer.start()

    async def send(self, flow: dict):
        """Send a single flow event to Kafka."""
        await self._ensure_connected()
        await self._producer.send(self.topic, value=flow)

    async def send_batch(self, flows: list[dict]):
        """Send a batch of flow events and flush."""
        await self._ensure_connected()
        for flow in flows:
            await self._producer.send(self.topic, value=flow)
        await self._producer.flush()

    async def close(self):
        """Stop the producer and release resources."""
        if self._producer:
            await self._producer.stop()
            self._producer = None
