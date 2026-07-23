"""Tests for RulesEngineModel."""

from __future__ import annotations

import pytest

from netguard.models.rules_engine import Rule, RulesEngineModel


@pytest.fixture
def engine():
    return RulesEngineModel()


def _empty_features() -> dict:
    return {
        "w60_unique_dst_ports": 0.0,
        "w60_unique_dst_ips": 0.0,
        "w60_connection_count": 0.0,
        "flag_syn_ratio": 0.0,
        "packets_bwd": 0.0,
        "proto_tcp": 0.0,
        "proto_udp": 0.0,
        "payload_entropy": 0.0,
        "port_well_known": 0.0,
        "duration_short": 0.0,
        "is_new_dst_ip": 0.0,
        "bytes_fwd": 0.0,
        "fwd_bwd_byte_ratio": 0.0,
    }


class TestBuiltInRules:
    def test_benign_scores_zero(self, engine):
        assert engine.score(_empty_features()) == 0.0
        assert engine.matched_rule is None

    def test_port_scan_rule(self, engine):
        feats = _empty_features()
        feats["w60_unique_dst_ports"] = 50.0
        s = engine.score(feats)
        assert s == 0.9
        assert engine.matched_rule == "port_scan"

    def test_syn_flood_rule(self, engine):
        feats = _empty_features()
        feats["flag_syn_ratio"] = 0.99
        feats["packets_bwd"] = 0.0
        feats["proto_tcp"] = 1.0
        assert engine.score(feats) == 0.95
        assert engine.matched_rule == "syn_flood"

    def test_brute_force_rule(self, engine):
        feats = _empty_features()
        feats["w60_connection_count"] = 30.0
        feats["duration_short"] = 1.0
        feats["w60_unique_dst_ips"] = 1.0
        assert engine.score(feats) == 0.85
        assert engine.matched_rule == "brute_force"

    def test_dns_tunnel_rule(self, engine):
        feats = _empty_features()
        feats["proto_udp"] = 1.0
        feats["payload_entropy"] = 7.5
        feats["port_well_known"] = 1.0
        assert engine.score(feats) == 0.8
        assert engine.matched_rule == "dns_tunnel"

    def test_exfiltration_rule(self, engine):
        feats = _empty_features()
        feats["is_new_dst_ip"] = 1.0
        feats["bytes_fwd"] = 100_000.0
        feats["fwd_bwd_byte_ratio"] = 0.99
        assert engine.score(feats) == 0.8
        assert engine.matched_rule == "exfiltration"

    def test_highest_confidence_wins(self, engine):
        # SYN flood (0.95) beats port_scan (0.9) when both trigger.
        feats = _empty_features()
        feats["w60_unique_dst_ports"] = 50.0
        feats["flag_syn_ratio"] = 0.99
        feats["proto_tcp"] = 1.0
        assert engine.score(feats) == 0.95
        assert engine.matched_rule == "syn_flood"


class TestCustomRules:
    def test_custom_rule_replaces_defaults(self):
        engine = RulesEngineModel(
            rules=[Rule(name="always_fires", confidence=0.5, predicate=lambda f: True)]
        )
        assert engine.score({}) == 0.5
        assert engine.matched_rule == "always_fires"

    def test_empty_rules_list_scores_zero(self):
        engine = RulesEngineModel(rules=[])
        assert engine.score({"anything": 1.0}) == 0.0
        assert engine.matched_rule is None

    def test_is_not_online(self, engine):
        assert engine.is_online is False
