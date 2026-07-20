"""Configuration models for NetGuard using pydantic-settings."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class KafkaConfig(BaseModel):
    brokers: list[str] = Field(default_factory=lambda: ["localhost:9092"])
    topic: str = "network-flows"
    group_id: str = "netguard-consumer"


class MemorySourceConfig(BaseModel):
    rate: float = 100.0  # flows per second


class SourceConfig(BaseModel):
    type: str = "memory"
    kafka: KafkaConfig = Field(default_factory=KafkaConfig)
    memory: MemorySourceConfig = Field(default_factory=MemorySourceConfig)


class StoreConfig(BaseModel):
    type: str = "memory"  # redis | memory
    redis_url: str = "redis://localhost:6379/0"


class FeaturesConfig(BaseModel):
    window_sizes: list[int] = Field(default_factory=lambda: [10, 30, 60, 300])
    store: StoreConfig = Field(default_factory=StoreConfig)


class ModelConfig(BaseModel):
    type: str = "isolation_forest"
    weight: float = 1.0
    enabled: bool = True
    params: dict[str, Any] = Field(default_factory=dict)


class ThresholdConfig(BaseModel):
    strategy: str = "adaptive"
    base_percentile: float = 95.0
    window_size: int = 1000
    fixed_value: float = 0.7


class OutputConfig(BaseModel):
    type: str = "console"
    min_severity: str = "low"
    url: str | None = None
    webhook_url: str | None = None
    path: str | None = None


class ServerConfig(BaseModel):
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = 8080


class NetGuardConfig(BaseSettings):
    source: SourceConfig = Field(default_factory=SourceConfig)
    features: FeaturesConfig = Field(default_factory=FeaturesConfig)
    models: list[ModelConfig] = Field(default_factory=lambda: [ModelConfig()])
    threshold: ThresholdConfig = Field(default_factory=ThresholdConfig)
    outputs: list[OutputConfig] = Field(default_factory=lambda: [OutputConfig()])
    server: ServerConfig = Field(default_factory=ServerConfig)

    model_config = {"env_prefix": "NETGUARD_", "env_nested_delimiter": "__"}

    @classmethod
    def from_yaml(cls, path: str) -> NetGuardConfig:
        """Load configuration from a YAML file."""
        data = yaml.safe_load(Path(path).read_text())
        return cls(**data)
