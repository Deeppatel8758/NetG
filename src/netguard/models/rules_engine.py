"""Hand-coded rules engine — deterministic signal for common attack patterns.

Runs alongside the ML models. Rules are cheap boolean checks against the
feature dict. When a rule fires the engine returns its confidence AND records
the rule name so the ensemble can label the alert.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from netguard.models.base import AnomalyModel


@dataclass
class Rule:
    """A single detection rule."""

    name: str
    """Name that surfaces as the alert's attack_type when this rule wins."""

    confidence: float
    """Score in [0, 1] returned when the rule matches."""

    predicate: Callable[[dict], bool]
    """Callable: (features) -> bool. True → the rule fires."""


def _default_rules() -> list[Rule]:
    return [
        # Horizontal port scan: one source hitting many ports fast.
        Rule(
            name="port_scan",
            confidence=0.9,
            predicate=lambda f: f.get("w60_unique_dst_ports", 0.0) >= 30.0,
        ),
        # SYN flood: nearly-all SYN packets, no return traffic.
        Rule(
            name="syn_flood",
            confidence=0.95,
            predicate=lambda f: (
                f.get("flag_syn_ratio", 0.0) > 0.9
                and f.get("packets_bwd", 0.0) == 0.0
                and f.get("proto_tcp", 0.0) == 1.0
            ),
        ),
        # Brute force: many short connections to the same host from one source.
        Rule(
            name="brute_force",
            confidence=0.85,
            predicate=lambda f: (
                f.get("w60_connection_count", 0.0) >= 20.0
                and f.get("duration_short", 0.0) == 1.0
                and f.get("w60_unique_dst_ips", 0.0) <= 2.0
            ),
        ),
        # DNS tunneling: high-entropy DNS payloads to port 53.
        Rule(
            name="dns_tunnel",
            confidence=0.8,
            predicate=lambda f: (
                f.get("proto_udp", 0.0) == 1.0
                and f.get("payload_entropy", 0.0) > 7.0
                and f.get("port_well_known", 0.0) == 1.0
            ),
        ),
        # Data exfiltration: large outbound to a first-seen destination.
        Rule(
            name="exfiltration",
            confidence=0.8,
            predicate=lambda f: (
                f.get("is_new_dst_ip", 0.0) == 1.0
                and f.get("bytes_fwd", 0.0) > 50_000
                and f.get("fwd_bwd_byte_ratio", 0.0) > 0.9
            ),
        ),
    ]


class RulesEngineModel(AnomalyModel):
    """Score = max confidence over matched rules. Zero if no rule matched."""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules if rules is not None else _default_rules()
        self.matched_rule: str | None = None

    @property
    def is_online(self) -> bool:
        return False

    def score(self, features: dict) -> float:
        best_conf = 0.0
        best_name: str | None = None
        for rule in self._rules:
            if rule.predicate(features) and rule.confidence > best_conf:
                best_conf = rule.confidence
                best_name = rule.name
        self.matched_rule = best_name
        return float(best_conf)
