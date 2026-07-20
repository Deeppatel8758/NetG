"""Synthetic traffic generation and dataset replay for testing NetGuard."""

from netguard.testing.attacks import AttackGenerator
from netguard.testing.generator import NetworkTrafficGenerator, TrafficProfile
from netguard.testing.scenarios import AttackScenario

__all__ = [
    "AttackGenerator",
    "AttackScenario",
    "CICIDSReplay",
    "NetworkTrafficGenerator",
    "TrafficProfile",
]


def __getattr__(name: str):
    if name == "CICIDSReplay":
        from netguard.testing.replay import CICIDSReplay
        return CICIDSReplay
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
