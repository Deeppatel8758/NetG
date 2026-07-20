"""Webhook output sink for sending alerts to external services."""

from __future__ import annotations

import json
import logging
from dataclasses import asdict

import aiohttp

from netguard.outputs.base import Alert, OutputSink

logger = logging.getLogger("netguard.outputs.webhook")


class WebhookOutput(OutputSink):
    """Posts alerts as JSON to a configured webhook URL."""

    def __init__(self, webhook_url: str, min_severity: str = "low") -> None:
        super().__init__(min_severity=min_severity)
        self._webhook_url = webhook_url
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        self._session = aiohttp.ClientSession()

    async def emit(self, alert: Alert) -> None:
        if not self.should_emit(alert):
            return

        if self._session is None:
            await self.start()

        payload = asdict(alert)
        payload["timestamp"] = alert.timestamp.isoformat()

        try:
            async with self._session.post(
                self._webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            ) as resp:
                if resp.status >= 400:
                    logger.warning(
                        "Webhook returned status %d for alert %s",
                        resp.status,
                        alert.id,
                    )
        except aiohttp.ClientError as e:
            logger.error("Failed to send alert %s to webhook: %s", alert.id, e)

    async def stop(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None
