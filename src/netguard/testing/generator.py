"""Synthetic normal network traffic generator for testing and benchmarking."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from dataclasses import dataclass, field
from typing import AsyncIterator

import numpy as np


@dataclass
class TrafficProfile:
    """Configuration for traffic generation characteristics."""

    subnets: list[str] = field(
        default_factory=lambda: ["10.0.1.0/24", "10.0.2.0/24", "172.16.0.0/24"]
    )
    protocol_weights: dict[str, float] = field(
        default_factory=lambda: {"TCP": 0.70, "UDP": 0.25, "ICMP": 0.05}
    )
    service_definitions: dict[str, dict] = field(
        default_factory=lambda: {
            "http": {"port": 80, "proto": "TCP", "weight": 0.30},
            "https": {"port": 443, "proto": "TCP", "weight": 0.35},
            "dns": {"port": 53, "proto": "UDP", "weight": 0.15},
            "ssh": {"port": 22, "proto": "TCP", "weight": 0.05},
            "smtp": {"port": 25, "proto": "TCP", "weight": 0.03},
            "mysql": {"port": 3306, "proto": "TCP", "weight": 0.04},
            "postgres": {"port": 5432, "proto": "TCP", "weight": 0.03},
            "ntp": {"port": 123, "proto": "UDP", "weight": 0.03},
            "rdp": {"port": 3389, "proto": "TCP", "weight": 0.02},
        }
    )
    base_rate: float = 100.0  # flows per second
    hourly_pattern: list[float] = field(
        default_factory=lambda: [
            # Multiplier for each hour (0-23), simulating business day patterns
            0.2, 0.15, 0.1, 0.1, 0.1, 0.15,   # 00-05: overnight low
            0.3, 0.5, 0.8, 1.0, 1.0, 0.9,     # 06-11: morning ramp-up
            0.7, 0.9, 1.0, 1.0, 0.9, 0.8,     # 12-17: afternoon
            0.6, 0.5, 0.4, 0.35, 0.3, 0.25,   # 18-23: evening wind-down
        ]
    )


# Host role probabilities
HOST_ROLE_WEIGHTS = {
    "workstation": 0.60,
    "server": 0.20,
    "database": 0.10,
    "dns": 0.05,
    "mail": 0.05,
}


class NetworkTrafficGenerator:
    """Generates realistic normal network flows for testing anomaly detectors."""

    def __init__(
        self,
        profile: TrafficProfile | None = None,
        seed: int = 42,
    ) -> None:
        self.profile = profile or TrafficProfile()
        self.rng = np.random.default_rng(seed)
        self._internal_ips = self._generate_internal_ips()
        self._external_ips = self._generate_external_ips(count=500)
        self._host_behaviors = self._assign_host_behaviors()

    def _generate_internal_ips(self) -> list[str]:
        """Generate internal IP pool from configured subnets."""
        ips: list[str] = []
        for subnet_str in self.profile.subnets:
            network = ipaddress.IPv4Network(subnet_str, strict=False)
            # Skip network and broadcast addresses
            hosts = [str(ip) for ip in network.hosts()]
            ips.extend(hosts)
        return ips

    def _generate_external_ips(self, count: int = 500) -> list[str]:
        """Generate external IP pool avoiding private address ranges."""
        external: list[str] = []
        while len(external) < count:
            octets = self.rng.integers(1, 255, size=4)
            ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"
            addr = ipaddress.IPv4Address(ip)
            # Skip private, loopback, link-local, multicast ranges
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                continue
            external.append(ip)
        return external

    def _assign_host_behaviors(self) -> dict[str, dict]:
        """Assign role and activity level to each internal IP."""
        behaviors: dict[str, dict] = {}
        roles = list(HOST_ROLE_WEIGHTS.keys())
        weights = list(HOST_ROLE_WEIGHTS.values())

        for ip in self._internal_ips:
            role = self.rng.choice(roles, p=weights)
            # Activity level: how often this host generates traffic (0.1-1.0)
            activity_level = float(self.rng.beta(2, 5) * 0.9 + 0.1)
            behaviors[ip] = {
                "role": role,
                "activity_level": activity_level,
                "typical_ports": self._get_typical_ports(role),
            }
        return behaviors

    def _get_typical_ports(self, role: str) -> list[int]:
        """Return typical destination ports based on host role."""
        port_map = {
            "workstation": [80, 443, 53, 8080, 8443, 3389],
            "server": [80, 443, 22, 8080, 8443, 9090, 9200],
            "database": [3306, 5432, 27017, 6379, 1433],
            "dns": [53, 953, 5353],
            "mail": [25, 465, 587, 993, 143, 110],
        }
        return port_map.get(role, [80, 443])

    def generate_normal_flow(self) -> dict:
        """Generate a single realistic normal network flow."""
        # Select source host weighted by activity level
        src_ip = self.rng.choice(self._internal_ips)
        src_behavior = self._host_behaviors[src_ip]

        # Determine direction: internal-to-external (70%) or internal-to-internal (30%)
        if self.rng.random() < 0.7:
            dst_ip = self.rng.choice(self._external_ips)
        else:
            dst_ip = self.rng.choice(self._internal_ips)
            # Avoid self-connections
            while dst_ip == src_ip:
                dst_ip = self.rng.choice(self._internal_ips)

        # Select protocol
        proto_names = list(self.profile.protocol_weights.keys())
        proto_probs = list(self.profile.protocol_weights.values())
        protocol = str(self.rng.choice(proto_names, p=proto_probs))

        # Select destination port based on role and service definitions
        typical_ports = src_behavior["typical_ports"]
        if self.rng.random() < 0.8:
            # Use a typical port for this role
            dst_port = int(self.rng.choice(typical_ports))
        else:
            # Use a service from the profile definitions
            services = list(self.profile.service_definitions.values())
            svc_weights = [s["weight"] for s in services]
            svc_weights_norm = np.array(svc_weights) / sum(svc_weights)
            chosen_svc = self.rng.choice(len(services), p=svc_weights_norm)
            dst_port = services[chosen_svc]["port"]
            protocol = services[chosen_svc]["proto"]

        # Source port: ephemeral range
        src_port = int(self.rng.integers(1024, 65535))

        # Duration: exponential distribution (most connections short)
        duration = float(self.rng.exponential(scale=2.0))
        duration = round(min(duration, 300.0), 4)  # Cap at 5 minutes

        # Bytes: lognormal distribution
        bytes_fwd = int(self.rng.lognormal(mean=7.0, sigma=1.5))  # ~1KB median
        bytes_bwd = int(self.rng.lognormal(mean=8.0, sigma=2.0))  # ~3KB median
        bytes_fwd = max(bytes_fwd, 40)  # Minimum TCP header
        bytes_bwd = max(bytes_bwd, 40)

        # Packets: derived from bytes with typical MTU considerations
        avg_packet_size_fwd = int(self.rng.integers(64, 1460))
        avg_packet_size_bwd = int(self.rng.integers(64, 1460))
        packets_fwd = max(1, bytes_fwd // avg_packet_size_fwd)
        packets_bwd = max(1, bytes_bwd // avg_packet_size_bwd)

        # TCP flags for normal connections
        tcp_flags = self._generate_flags(protocol, "normal")

        # Payload entropy: normal traffic has moderate entropy (3.5-6.5)
        payload_entropy = float(self.rng.normal(loc=5.0, scale=0.8))
        payload_entropy = round(max(0.0, min(8.0, payload_entropy)), 4)

        return {
            "timestamp": time.time(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "duration": duration,
            "bytes_fwd": bytes_fwd,
            "bytes_bwd": bytes_bwd,
            "packets_fwd": packets_fwd,
            "packets_bwd": packets_bwd,
            "tcp_flags": tcp_flags,
            "payload_entropy": payload_entropy,
            "label": "benign",
            "attack_type": None,
        }

    def _generate_flags(self, protocol: str, context: str) -> dict:
        """Generate realistic TCP flags based on protocol and connection context."""
        if protocol != "TCP":
            return {
                "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0,
                "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0,
            }

        if context == "normal":
            # Normal connection: SYN in handshake, then ACK+PSH for data, FIN to close
            return {
                "SYN": int(self.rng.integers(1, 3)),
                "ACK": int(self.rng.integers(5, 50)),
                "FIN": int(self.rng.integers(1, 3)),
                "RST": int(self.rng.choice([0, 0, 0, 0, 1])),  # Rare RST
                "PSH": int(self.rng.integers(2, 20)),
                "URG": 0,
                "ECE": 0,
                "CWR": 0,
            }
        elif context == "syn_only":
            return {
                "SYN": 1, "ACK": 0, "FIN": 0, "RST": 0,
                "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0,
            }
        elif context == "rst":
            return {
                "SYN": 1, "ACK": 0, "FIN": 0, "RST": 1,
                "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0,
            }
        else:
            return {
                "SYN": 1, "ACK": int(self.rng.integers(1, 10)),
                "FIN": 1, "RST": 0, "PSH": int(self.rng.integers(1, 5)),
                "URG": 0, "ECE": 0, "CWR": 0,
            }

    async def stream(
        self,
        rate: float | None = None,
        include_attacks: bool = False,
    ) -> AsyncIterator[dict]:
        """Async generator that yields flows at configured rate with time-of-day variation.

        Args:
            rate: Flows per second override. Defaults to profile base_rate.
            include_attacks: If True, attack flows may be mixed in (requires AttackGenerator).
        """
        effective_rate = rate or self.profile.base_rate

        while True:
            # Apply hourly pattern multiplier
            current_hour = int(time.localtime().tm_hour)
            hour_multiplier = self.profile.hourly_pattern[current_hour]
            adjusted_rate = effective_rate * hour_multiplier

            # Calculate inter-flow delay with jitter
            if adjusted_rate > 0:
                base_delay = 1.0 / adjusted_rate
                # Add some randomness to avoid perfectly regular patterns
                jitter = float(self.rng.exponential(scale=base_delay * 0.1))
                delay = base_delay + jitter
            else:
                delay = 1.0

            yield self.generate_normal_flow()
            await asyncio.sleep(delay)
