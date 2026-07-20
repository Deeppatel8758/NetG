"""Source adapters for ingesting network flow data."""

from netguard.adapters.base import NetworkFlow, SourceAdapter
from netguard.adapters.memory_adapter import MemoryAdapter

__all__ = ["SourceAdapter", "MemoryAdapter", "NetworkFlow"]


def __getattr__(name: str):
    if name == "KafkaAdapter":
        from netguard.adapters.kafka_adapter import KafkaAdapter
        return KafkaAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
