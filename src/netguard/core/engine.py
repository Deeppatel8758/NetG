"""Main NetGuard detection engine."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from netguard.core.config import NetGuardConfig
from netguard.core.pipeline import Pipeline
from netguard.models.base import AnomalyModel
from netguard.outputs.base import Alert, OutputSink

logger = logging.getLogger("netguard")


class NetGuard:
    """Core detection engine that orchestrates the anomaly detection pipeline."""

    def __init__(
        self,
        config: NetGuardConfig | None = None,
        source: Any = None,
        outputs: list[OutputSink] | None = None,
    ) -> None:
        self.config = config or NetGuardConfig()
        self._source = source
        self._models: list[tuple[AnomalyModel, float]] = []
        self._outputs: list[OutputSink] = outputs or []
        self._alert_handlers: list[Callable[[Alert], Any]] = []
        self._pipeline: Pipeline | None = None
        self._running = False

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

    @classmethod
    def from_config(cls, path: str) -> NetGuard:
        """Create a NetGuard instance from a YAML configuration file."""
        config = NetGuardConfig.from_yaml(path)
        return cls(config=config)

    def add_model(self, model: AnomalyModel, weight: float = 1.0) -> None:
        """Register an anomaly detection model with an ensemble weight."""
        self._models.append((model, weight))

    def add_output(self, output: OutputSink) -> None:
        """Register an output sink for alerts."""
        self._outputs.append(output)

    def on_alert(self, callback: Callable[[Alert], Any]) -> None:
        """Register a callback to be invoked on each alert."""
        self._alert_handlers.append(callback)

    async def start(self) -> None:
        """Start the streaming detection pipeline."""
        logger.info("Starting NetGuard engine...")
        self._running = True

        self._pipeline = Pipeline(
            config=self.config,
            source=self._source,
            models=self._models,
            outputs=self._outputs,
        )

        try:
            await self._pipeline.run()
        except asyncio.CancelledError:
            logger.info("Pipeline cancelled.")
        finally:
            self._running = False

    async def stop(self) -> None:
        """Gracefully shut down the engine."""
        logger.info("Stopping NetGuard engine...")
        self._running = False
        if self._pipeline:
            await self._pipeline.stop()
