"""Per-flow feature extraction.

Pure, stateless transforms from a NetworkFlow into scalar features. No store
lookups or side effects — every function here is safe to call in any order.
"""

from __future__ import annotations

from netguard.adapters.base import NetworkFlow

TCP_FLAG_NAMES = ("SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR")
PROTOCOLS = ("TCP", "UDP", "ICMP")

DURATION_SHORT_SEC = 1.0
DURATION_MEDIUM_SEC = 30.0

PORT_WELL_KNOWN_MAX = 1023
PORT_REGISTERED_MAX = 49151


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def bytes_per_packet(flow: NetworkFlow) -> tuple[float, float]:
    """Return (fwd_bpp, bwd_bpp). 0.0 when packet count is zero."""
    return (
        _safe_ratio(flow.bytes_fwd, flow.packets_fwd),
        _safe_ratio(flow.bytes_bwd, flow.packets_bwd),
    )


def fwd_bwd_ratios(flow: NetworkFlow) -> tuple[float, float]:
    """Return (byte_ratio, packet_ratio) as fwd / (fwd + bwd)."""
    total_bytes = flow.bytes_fwd + flow.bytes_bwd
    total_pkts = flow.packets_fwd + flow.packets_bwd
    return (
        _safe_ratio(flow.bytes_fwd, total_bytes),
        _safe_ratio(flow.packets_fwd, total_pkts),
    )


def tcp_flag_ratios(flow: NetworkFlow) -> dict[str, float]:
    """Return one ratio per TCP flag (flag_count / total_packets).

    For non-TCP flows or zero-packet flows every ratio is 0.0.
    """
    total_pkts = flow.packets_fwd + flow.packets_bwd
    if flow.protocol != "TCP" or total_pkts <= 0:
        return {f"flag_{name.lower()}_ratio": 0.0 for name in TCP_FLAG_NAMES}

    return {
        f"flag_{name.lower()}_ratio": _safe_ratio(flow.tcp_flags.get(name, 0), total_pkts)
        for name in TCP_FLAG_NAMES
    }


def protocol_one_hot(flow: NetworkFlow) -> dict[str, float]:
    """One-hot encode the flow's protocol. Unknown protocols → all zeros."""
    return {f"proto_{p.lower()}": 1.0 if flow.protocol == p else 0.0 for p in PROTOCOLS}


def duration_bucket(flow: NetworkFlow) -> dict[str, float]:
    """One-hot bucket the duration: short (<1s), medium (<30s), long (>=30s)."""
    d = flow.duration
    return {
        "duration_short": 1.0 if d < DURATION_SHORT_SEC else 0.0,
        "duration_medium": 1.0 if DURATION_SHORT_SEC <= d < DURATION_MEDIUM_SEC else 0.0,
        "duration_long": 1.0 if d >= DURATION_MEDIUM_SEC else 0.0,
    }


def dst_port_category(flow: NetworkFlow) -> dict[str, float]:
    """Categorize dst_port into well-known / registered / ephemeral (one-hot)."""
    port = flow.dst_port
    return {
        "port_well_known": 1.0 if 0 <= port <= PORT_WELL_KNOWN_MAX else 0.0,
        "port_registered": 1.0 if PORT_WELL_KNOWN_MAX < port <= PORT_REGISTERED_MAX else 0.0,
        "port_ephemeral": 1.0 if port > PORT_REGISTERED_MAX else 0.0,
    }


def extract_flow_features(flow: NetworkFlow) -> dict[str, float]:
    """Compute all per-flow features and return them as a flat dict."""
    fwd_bpp, bwd_bpp = bytes_per_packet(flow)
    byte_ratio, pkt_ratio = fwd_bwd_ratios(flow)

    features: dict[str, float] = {
        "bytes_fwd": float(flow.bytes_fwd),
        "bytes_bwd": float(flow.bytes_bwd),
        "packets_fwd": float(flow.packets_fwd),
        "packets_bwd": float(flow.packets_bwd),
        "duration": float(flow.duration),
        "bytes_per_packet_fwd": fwd_bpp,
        "bytes_per_packet_bwd": bwd_bpp,
        "fwd_bwd_byte_ratio": byte_ratio,
        "fwd_bwd_packet_ratio": pkt_ratio,
        "payload_entropy": float(flow.payload_entropy),
    }
    features.update(tcp_flag_ratios(flow))
    features.update(protocol_one_hot(flow))
    features.update(duration_bucket(flow))
    features.update(dst_port_category(flow))
    return features
