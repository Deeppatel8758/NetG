
"""Unit tests for per-flow feature extraction."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netguard.adapters.base import NetworkFlow
from netguard.features.flow_features import (
    TCP_FLAG_NAMES,
    bytes_per_packet,
    dst_port_category,
    duration_bucket,
    extract_flow_features,
    fwd_bwd_ratios,
    protocol_one_hot,
    tcp_flag_ratios,
)


def _flow(**overrides) -> NetworkFlow:
    defaults = dict(
        timestamp=datetime(2026, 7, 20, 12, 0, 0, tzinfo=timezone.utc),
        src_ip="10.0.1.10",
        dst_ip="10.0.1.20",
        src_port=45123,
        dst_port=443,
        protocol="TCP",
        duration=1.5,
        bytes_fwd=1000,
        bytes_bwd=2000,
        packets_fwd=10,
        packets_bwd=20,
        tcp_flags={"SYN": 1, "ACK": 15, "FIN": 1, "RST": 0, "PSH": 5, "URG": 0},
        payload_entropy=5.0,
    )
    defaults.update(overrides)
    return NetworkFlow(**defaults)


class TestBytesPerPacket:
    def test_normal(self):
        fwd, bwd = bytes_per_packet(_flow())
        assert fwd == 100.0
        assert bwd == 100.0

    def test_zero_packets(self):
        fwd, bwd = bytes_per_packet(_flow(packets_fwd=0, packets_bwd=0))
        assert fwd == 0.0
        assert bwd == 0.0


class TestFwdBwdRatios:
    def test_balanced(self):
        byte_ratio, pkt_ratio = fwd_bwd_ratios(_flow(bytes_fwd=500, bytes_bwd=500, packets_fwd=5, packets_bwd=5))
        assert byte_ratio == 0.5
        assert pkt_ratio == 0.5

    def test_all_fwd(self):
        byte_ratio, pkt_ratio = fwd_bwd_ratios(_flow(bytes_fwd=1000, bytes_bwd=0, packets_fwd=10, packets_bwd=0))
        assert byte_ratio == 1.0
        assert pkt_ratio == 1.0

    def test_zero_traffic(self):
        byte_ratio, pkt_ratio = fwd_bwd_ratios(_flow(bytes_fwd=0, bytes_bwd=0, packets_fwd=0, packets_bwd=0))
        assert byte_ratio == 0.0
        assert pkt_ratio == 0.0


class TestTcpFlagRatios:
    def test_ratios_sum_correctly(self):
        # 10 fwd + 20 bwd = 30 total pkts; SYN=1 → 1/30
        ratios = tcp_flag_ratios(_flow())
        assert ratios["flag_syn_ratio"] == pytest.approx(1 / 30)
        assert ratios["flag_ack_ratio"] == pytest.approx(15 / 30)
        assert ratios["flag_psh_ratio"] == pytest.approx(5 / 30)
        # Every flag name is represented
        for name in TCP_FLAG_NAMES:
            assert f"flag_{name.lower()}_ratio" in ratios

    def test_non_tcp_zeros_all(self):
        ratios = tcp_flag_ratios(_flow(protocol="UDP"))
        assert all(v == 0.0 for v in ratios.values())

    def test_zero_packets_zeros_all(self):
        ratios = tcp_flag_ratios(_flow(packets_fwd=0, packets_bwd=0))
        assert all(v == 0.0 for v in ratios.values())


class TestProtocolOneHot:
    @pytest.mark.parametrize("proto,hot", [("TCP", "proto_tcp"), ("UDP", "proto_udp"), ("ICMP", "proto_icmp")])
    def test_known(self, proto, hot):
        oh = protocol_one_hot(_flow(protocol=proto))
        assert oh[hot] == 1.0
        assert sum(oh.values()) == 1.0

    def test_unknown(self):
        oh = protocol_one_hot(_flow(protocol="SCTP"))
        assert sum(oh.values()) == 0.0


class TestDurationBucket:
    @pytest.mark.parametrize("d,key", [(0.5, "duration_short"), (10.0, "duration_medium"), (60.0, "duration_long")])
    def test_buckets(self, d, key):
        b = duration_bucket(_flow(duration=d))
        assert b[key] == 1.0
        assert sum(b.values()) == 1.0

    def test_boundary_at_1s_is_medium(self):
        b = duration_bucket(_flow(duration=1.0))
        assert b["duration_medium"] == 1.0

    def test_boundary_at_30s_is_long(self):
        b = duration_bucket(_flow(duration=30.0))
        assert b["duration_long"] == 1.0


class TestDstPortCategory:
    @pytest.mark.parametrize("port,key", [(22, "port_well_known"), (8080, "port_registered"), (55555, "port_ephemeral")])
    def test_categories(self, port, key):
        c = dst_port_category(_flow(dst_port=port))
        assert c[key] == 1.0
        assert sum(c.values()) == 1.0


class TestExtractFlowFeatures:
    def test_returns_flat_dict(self):
        feats = extract_flow_features(_flow())
        # Should be a flat dict of str→float
        assert all(isinstance(k, str) and isinstance(v, float) for k, v in feats.items())

    def test_includes_all_expected_keys(self):
        feats = extract_flow_features(_flow())
        expected = {
            "bytes_fwd", "bytes_bwd", "packets_fwd", "packets_bwd", "duration",
            "bytes_per_packet_fwd", "bytes_per_packet_bwd",
            "fwd_bwd_byte_ratio", "fwd_bwd_packet_ratio",
            "payload_entropy",
            "proto_tcp", "proto_udp", "proto_icmp",
            "duration_short", "duration_medium", "duration_long",
            "port_well_known", "port_registered", "port_ephemeral",
        }
        assert expected.issubset(feats.keys())
        assert all(f"flag_{n.lower()}_ratio" in feats for n in TCP_FLAG_NAMES)

    def test_deterministic(self):
        f = _flow()
        assert extract_flow_features(f) == extract_flow_features(f)
