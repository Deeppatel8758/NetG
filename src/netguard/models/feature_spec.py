"""Feature vector contract — single source of truth for model I/O.

All models that take a fixed-length numeric vector (Autoencoder, XGBoost) import
FEATURE_ORDER from here. The order is frozen; adding a feature means bumping
model versions and retraining.
"""

from __future__ import annotations

import numpy as np

FEATURE_ORDER: tuple[str, ...] = (
    "bytes_bwd",
    "bytes_fwd",
    "bytes_per_packet_bwd",
    "bytes_per_packet_fwd",
    "duration",
    "duration_long",
    "duration_medium",
    "duration_short",
    "flag_ack_ratio",
    "flag_cwr_ratio",
    "flag_ece_ratio",
    "flag_fin_ratio",
    "flag_psh_ratio",
    "flag_rst_ratio",
    "flag_syn_ratio",
    "flag_urg_ratio",
    "fwd_bwd_byte_ratio",
    "fwd_bwd_packet_ratio",
    "is_new_dst_ip",
    "is_new_dst_port",
    "packets_bwd",
    "packets_fwd",
    "payload_entropy",
    "port_ephemeral",
    "port_registered",
    "port_well_known",
    "proto_icmp",
    "proto_tcp",
    "proto_udp",
    "w60_bytes_in",
    "w60_bytes_out",
    "w60_connection_count",
    "w60_syn_ratio",
    "w60_unique_dst_ips",
    "w60_unique_dst_ports",
    "w300_bytes_in",
    "w300_bytes_out",
    "w300_connection_count",
    "w300_syn_ratio",
    "w300_unique_dst_ips",
    "w300_unique_dst_ports",
)

FEATURE_COUNT = len(FEATURE_ORDER)

ATTACK_CLASSES: tuple[str, ...] = (
    "benign",
    "port_scan",
    "syn_flood",
    "brute_force",
    "c2_beacon",
    "lateral_movement",
    "dns_tunnel",
    "exfiltration",
)

CLASS_COUNT = len(ATTACK_CLASSES)


def to_vector(features: dict[str, float]) -> np.ndarray:
    """Project a feature dict into a fixed-order float32 vector.

    Missing keys default to 0.0 — matches how ``flow_features`` already returns
    zeros for non-TCP/zero-packet flows.
    """
    return np.fromiter(
        (float(features.get(name, 0.0)) for name in FEATURE_ORDER),
        dtype=np.float32,
        count=FEATURE_COUNT,
    )
