"""In-memory adapter for demo and testing purposes."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from netguard.adapters.base import SourceAdapter


class MemoryAdapter(SourceAdapter):
    """Yields flows from a NetworkTrafficGenerator at a configurable rate."""

    def __init__(
        self,
        generator: Any = None,
        rate: float = 100.0,
    ) -> None:
        self._generator = generator
        self._rate = rate

    async def stream(self) -> AsyncIterator[dict]:
        """Yield flow dicts from the generator, throttled to the configured rate."""
        if self._generator is None:
            return

        interval = 1.0 / self._rate if self._rate > 0 else 0.0

        while True:
            flow = self._generator.generate_normal_flow()
            yield flow
            if interval > 0:
                await asyncio.sleep(interval)
