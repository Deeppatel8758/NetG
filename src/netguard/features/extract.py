"""Feature extraction orchestrator.

Wires together three feature sources into one call:
- Per-flow features (pure, stateless).
- Windowed aggregates from the feature store (60s + 300s per src IP).
- First-seen booleans (has this src talked to this dst_ip/dst_port before?).

Records the flow into the store *after* computing first-seen so the current
flow doesn't count itself as "already seen".
"""

from __future__ import annotations

from netguard.adapters.base import NetworkFlow
from netguard.core.config import FeaturesConfig, StoreConfig
from netguard.features.flow_features import extract_flow_features
from netguard.features.store import FeatureStore, MemoryStore, RedisStore

DEFAULT_WINDOWS_SEC = (60, 300)


def build_store(cfg: StoreConfig) -> FeatureStore:
    """Instantiate the configured feature store backend."""
    if cfg.type == "redis":
        return RedisStore(url=cfg.redis_url)
    if cfg.type == "memory":
        return MemoryStore()
    raise ValueError(f"Unknown feature store type: {cfg.type!r}")


class FeatureExtractor:
    """Enrich each flow with per-flow, windowed, and first-seen features."""

    def __init__(
        self,
        store: FeatureStore,
        windows_sec: tuple[int, ...] = DEFAULT_WINDOWS_SEC,
    ) -> None:
        self._store = store
        self._windows_sec = windows_sec

    @classmethod
    def from_config(cls, cfg: FeaturesConfig) -> FeatureExtractor:
        store = build_store(cfg.store)
        # window_sizes come from config; fall back to defaults if unset.
        windows = tuple(cfg.window_sizes) if cfg.window_sizes else DEFAULT_WINDOWS_SEC
        return cls(store=store, windows_sec=windows)

    async def extract(self, flow: NetworkFlow) -> dict[str, float]:
        """Return the full feature vector for ``flow`` and update the store."""
        features = extract_flow_features(flow)

        # First-seen booleans BEFORE recording, so we don't count this flow as prior history.
        is_new_dst_ip = await self._store.is_new_and_mark("dst_ip", flow.src_ip, flow.dst_ip)
        is_new_dst_port = await self._store.is_new_and_mark("dst_port", flow.src_ip, flow.dst_port)
        features["is_new_dst_ip"] = 1.0 if is_new_dst_ip else 0.0
        features["is_new_dst_port"] = 1.0 if is_new_dst_port else 0.0

        # Windowed aggregates come from the store's history up to this point.
        # We record this flow AFTER querying so windows reflect prior activity;
        # this keeps a single flow from inflating its own aggregates.
        ts = flow.timestamp.timestamp()
        for window_sec in self._windows_sec:
            stats = await self._store.window_stats(flow.src_ip, window_sec, now=ts)
            features.update(stats.as_features(window_sec))

        is_syn_only = (
            flow.protocol == "TCP"
            and flow.tcp_flags.get("SYN", 0) > 0
            and flow.tcp_flags.get("ACK", 0) == 0
        )
        await self._store.record_flow(
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            bytes_out=flow.bytes_fwd,
            bytes_in=flow.bytes_bwd,
            is_syn_only=is_syn_only,
            timestamp=ts,
        )

        return features

    async def close(self) -> None:
        await self._store.close()
