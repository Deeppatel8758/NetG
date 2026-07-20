"""Attack pattern generators for testing anomaly detection models."""

from __future__ import annotations

import asyncio
import time
from typing import AsyncIterator

import numpy as np

from netguard.testing.generator import NetworkTrafficGenerator


class AttackGenerator:
    """Generates realistic attack traffic patterns for testing detection capabilities."""

    def __init__(self, base_generator: NetworkTrafficGenerator) -> None:
        self.base = base_generator
        self.rng = base_generator.rng

    async def inject_random(self) -> AsyncIterator[dict]:
        """Pick a random attack type and generate flows."""
        attack_methods = [
            self.generate_port_scan,
            self.generate_syn_flood,
            self.generate_brute_force,
            self.generate_c2_beacon,
            self.generate_lateral_movement,
            self.generate_dns_tunnel,
            self.generate_exfiltration,
        ]
        chosen = self.rng.choice(attack_methods)

        # Use random IPs from pools
        src_ip = self.rng.choice(self.base._internal_ips)
        dst_ip = self.rng.choice(self.base._external_ips)

        async for flow in chosen(src_ip=src_ip, target_ip=dst_ip):
            yield flow

    async def generate_port_scan(
        self,
        src_ip: str | None = None,
        target_ip: str | None = None,
        ports: int = 100,
        scan_type: str = "syn",
    ) -> AsyncIterator[dict]:
        """Generate port scan attack: rapid probing of many ports on a target.

        Args:
            src_ip: Source IP of the scanner.
            target_ip: Target IP being scanned.
            ports: Number of ports to scan.
            scan_type: Type of scan ('syn', 'connect', 'fin').
        """
        src_ip = src_ip or self.rng.choice(self.base._external_ips)
        target_ip = target_ip or self.rng.choice(self.base._internal_ips)

        # Generate a list of target ports (mix of common + random)
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                        993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443]
        random_ports = list(self.rng.integers(1, 65535, size=max(0, ports - len(common_ports))))
        scan_ports = (common_ports + random_ports)[:ports]
        self.rng.shuffle(scan_ports)

        for port in scan_ports:
            # Port scans are very fast with minimal data transfer
            if scan_type == "syn":
                flags = {"SYN": 1, "ACK": 0, "FIN": 0, "RST": 0,
                         "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0}
            elif scan_type == "fin":
                flags = {"SYN": 0, "ACK": 0, "FIN": 1, "RST": 0,
                         "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0}
            else:  # connect scan
                flags = {"SYN": 1, "ACK": 1, "FIN": 1, "RST": 0,
                         "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0}

            yield {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": target_ip,
                "src_port": int(self.rng.integers(1024, 65535)),
                "dst_port": int(port),
                "protocol": "TCP",
                "duration": round(float(self.rng.exponential(0.01)), 4),
                "bytes_fwd": int(self.rng.integers(40, 60)),
                "bytes_bwd": int(self.rng.integers(0, 44)),  # RST or no response
                "packets_fwd": 1,
                "packets_bwd": int(self.rng.choice([0, 1])),
                "tcp_flags": flags,
                "payload_entropy": 0.0,
                "label": "malicious",
                "attack_type": "port_scan",
            }

            # Very short delay between probes (fast scanner)
            await asyncio.sleep(float(self.rng.exponential(0.005)))

    async def generate_syn_flood(
        self,
        target_ip: str | None = None,
        target_port: int = 80,
        duration_sec: float = 30.0,
        rate: int = 1000,
        **kwargs,
    ) -> AsyncIterator[dict]:
        """Generate SYN flood DDoS attack: massive volume of SYN packets.

        Args:
            target_ip: Target IP being flooded.
            target_port: Target port (usually HTTP/HTTPS).
            duration_sec: Duration of the flood in seconds.
            rate: SYN packets per second.
        """
        target_ip = target_ip or self.rng.choice(self.base._internal_ips)
        start_time = time.time()
        delay = 1.0 / rate

        while (time.time() - start_time) < duration_sec:
            # Spoofed source IPs (random)
            spoofed_src = f"{self.rng.integers(1, 254)}.{self.rng.integers(1, 254)}.{self.rng.integers(1, 254)}.{self.rng.integers(1, 254)}"

            yield {
                "timestamp": time.time(),
                "src_ip": spoofed_src,
                "dst_ip": target_ip,
                "src_port": int(self.rng.integers(1024, 65535)),
                "dst_port": target_port,
                "protocol": "TCP",
                "duration": 0.0,
                "bytes_fwd": 40,  # Bare SYN packet
                "bytes_bwd": 0,  # No response (half-open)
                "packets_fwd": 1,
                "packets_bwd": 0,
                "tcp_flags": {
                    "SYN": 1, "ACK": 0, "FIN": 0, "RST": 0,
                    "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0,
                },
                "payload_entropy": 0.0,
                "label": "malicious",
                "attack_type": "syn_flood",
            }

            await asyncio.sleep(delay)

    async def generate_brute_force(
        self,
        target_ip: str | None = None,
        service_port: int = 22,
        attempts: int = 50,
        src_ip: str | None = None,
        **kwargs,
    ) -> AsyncIterator[dict]:
        """Generate brute force authentication attack: repeated login attempts.

        Args:
            target_ip: Target IP running the service.
            service_port: Port of the target service (SSH=22, RDP=3389, etc.).
            attempts: Number of authentication attempts.
            src_ip: Source IP of the attacker.
        """
        target_ip = target_ip or self.rng.choice(self.base._internal_ips)
        src_ip = src_ip or self.rng.choice(self.base._external_ips)

        for i in range(attempts):
            # Each attempt: short connection, small payload (credentials), quick rejection
            # Slight variation in timing to simulate real brute-force tools
            duration = round(float(self.rng.uniform(0.1, 0.8)), 4)

            yield {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": target_ip,
                "src_port": int(self.rng.integers(1024, 65535)),
                "dst_port": service_port,
                "protocol": "TCP",
                "duration": duration,
                "bytes_fwd": int(self.rng.integers(100, 300)),  # Username + password
                "bytes_bwd": int(self.rng.integers(50, 150)),   # Auth rejection
                "packets_fwd": int(self.rng.integers(3, 8)),
                "packets_bwd": int(self.rng.integers(2, 6)),
                "tcp_flags": {
                    "SYN": 1, "ACK": int(self.rng.integers(3, 8)),
                    "FIN": 1, "RST": int(self.rng.choice([0, 1])),
                    "PSH": int(self.rng.integers(1, 4)), "URG": 0,
                    "ECE": 0, "CWR": 0,
                },
                "payload_entropy": round(float(self.rng.uniform(4.5, 6.0)), 4),
                "label": "malicious",
                "attack_type": "brute_force",
            }

            # Delay between attempts: tools like Hydra have configurable delays
            await asyncio.sleep(float(self.rng.uniform(0.5, 3.0)))

    async def generate_c2_beacon(
        self,
        infected_ip: str | None = None,
        c2_server: str | None = None,
        beacon_count: int = 30,
        interval_sec: float = 60.0,
        **kwargs,
    ) -> AsyncIterator[dict]:
        """Generate C2 (Command and Control) beacon traffic: periodic callbacks.

        Args:
            infected_ip: Compromised internal host.
            c2_server: External C2 server IP.
            beacon_count: Number of beacon check-ins.
            interval_sec: Average seconds between beacons.
        """
        infected_ip = infected_ip or self.rng.choice(self.base._internal_ips)
        c2_server = c2_server or self.rng.choice(self.base._external_ips)

        for i in range(beacon_count):
            # C2 beacons: regular interval with slight jitter, small consistent payload
            jitter = float(self.rng.normal(0, interval_sec * 0.1))
            actual_interval = max(1.0, interval_sec + jitter)

            # Beacons use HTTPS to blend in, small payload with commands
            has_command = self.rng.random() < 0.2  # 20% chance of receiving a command
            bytes_bwd = int(self.rng.integers(500, 2000)) if has_command else int(self.rng.integers(50, 200))

            yield {
                "timestamp": time.time(),
                "src_ip": infected_ip,
                "dst_ip": c2_server,
                "src_port": int(self.rng.integers(1024, 65535)),
                "dst_port": 443,
                "protocol": "TCP",
                "duration": round(float(self.rng.uniform(0.5, 3.0)), 4),
                "bytes_fwd": int(self.rng.integers(100, 400)),  # Check-in data
                "bytes_bwd": bytes_bwd,
                "packets_fwd": int(self.rng.integers(2, 6)),
                "packets_bwd": int(self.rng.integers(2, 8)),
                "tcp_flags": {
                    "SYN": 1, "ACK": int(self.rng.integers(4, 12)),
                    "FIN": 1, "RST": 0,
                    "PSH": int(self.rng.integers(2, 6)), "URG": 0,
                    "ECE": 0, "CWR": 0,
                },
                "payload_entropy": round(float(self.rng.uniform(6.5, 7.8)), 4),  # Encrypted
                "label": "malicious",
                "attack_type": "c2_beacon",
            }

            await asyncio.sleep(actual_interval)

    async def generate_lateral_movement(
        self,
        compromised_ip: str | None = None,
        targets: int = 5,
        **kwargs,
    ) -> AsyncIterator[dict]:
        """Generate lateral movement: internal pivoting on admin ports.

        Args:
            compromised_ip: The initially compromised host.
            targets: Number of internal hosts to pivot to.
        """
        compromised_ip = compromised_ip or self.rng.choice(self.base._internal_ips)

        # Select target internal hosts (excluding self)
        available_targets = [ip for ip in self.base._internal_ips if ip != compromised_ip]
        target_ips = list(self.rng.choice(available_targets, size=min(targets, len(available_targets)), replace=False))

        # Admin/management ports used for lateral movement
        admin_ports = [22, 135, 139, 445, 3389, 5985, 5986]

        for target_ip in target_ips:
            # First: reconnaissance (quick probe of admin ports)
            for port in self.rng.choice(admin_ports, size=min(3, len(admin_ports)), replace=False):
                yield {
                    "timestamp": time.time(),
                    "src_ip": compromised_ip,
                    "dst_ip": target_ip,
                    "src_port": int(self.rng.integers(1024, 65535)),
                    "dst_port": int(port),
                    "protocol": "TCP",
                    "duration": round(float(self.rng.exponential(0.05)), 4),
                    "bytes_fwd": int(self.rng.integers(40, 80)),
                    "bytes_bwd": int(self.rng.integers(40, 80)),
                    "packets_fwd": 1,
                    "packets_bwd": 1,
                    "tcp_flags": {
                        "SYN": 1, "ACK": 1, "FIN": 0, "RST": 0,
                        "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0,
                    },
                    "payload_entropy": 0.0,
                    "label": "malicious",
                    "attack_type": "lateral_movement",
                }
                await asyncio.sleep(float(self.rng.uniform(0.1, 0.5)))

            # Then: exploitation/login on discovered open port
            exploit_port = int(self.rng.choice(admin_ports))
            yield {
                "timestamp": time.time(),
                "src_ip": compromised_ip,
                "dst_ip": target_ip,
                "src_port": int(self.rng.integers(1024, 65535)),
                "dst_port": exploit_port,
                "protocol": "TCP",
                "duration": round(float(self.rng.uniform(2.0, 15.0)), 4),
                "bytes_fwd": int(self.rng.integers(2000, 10000)),  # Tool/payload upload
                "bytes_bwd": int(self.rng.integers(500, 3000)),
                "packets_fwd": int(self.rng.integers(10, 50)),
                "packets_bwd": int(self.rng.integers(5, 25)),
                "tcp_flags": {
                    "SYN": 1, "ACK": int(self.rng.integers(10, 40)),
                    "FIN": 1, "RST": 0,
                    "PSH": int(self.rng.integers(5, 20)), "URG": 0,
                    "ECE": 0, "CWR": 0,
                },
                "payload_entropy": round(float(self.rng.uniform(6.0, 7.5)), 4),
                "label": "malicious",
                "attack_type": "lateral_movement",
            }

            # Delay between target pivots
            await asyncio.sleep(float(self.rng.uniform(5.0, 30.0)))

    async def generate_dns_tunnel(
        self,
        infected_ip: str | None = None,
        queries: int = 100,
        **kwargs,
    ) -> AsyncIterator[dict]:
        """Generate DNS tunneling: high-entropy DNS queries for data exfiltration.

        Args:
            infected_ip: Compromised internal host.
            queries: Number of DNS tunnel queries.
        """
        infected_ip = infected_ip or self.rng.choice(self.base._internal_ips)

        # DNS server (internal or external)
        dns_server = self.rng.choice(self.base._external_ips)

        for i in range(queries):
            # DNS tunnel queries have high entropy (encoded data in subdomain)
            # and are slightly larger than normal DNS queries
            yield {
                "timestamp": time.time(),
                "src_ip": infected_ip,
                "dst_ip": dns_server,
                "src_port": int(self.rng.integers(1024, 65535)),
                "dst_port": 53,
                "protocol": "UDP",
                "duration": round(float(self.rng.uniform(0.01, 0.2)), 4),
                "bytes_fwd": int(self.rng.integers(80, 255)),   # Encoded data in query
                "bytes_bwd": int(self.rng.integers(100, 512)),  # Response with encoded data
                "packets_fwd": 1,
                "packets_bwd": 1,
                "tcp_flags": {
                    "SYN": 0, "ACK": 0, "FIN": 0, "RST": 0,
                    "PSH": 0, "URG": 0, "ECE": 0, "CWR": 0,
                },
                "payload_entropy": round(float(self.rng.uniform(6.8, 7.9)), 4),  # Very high entropy
                "label": "malicious",
                "attack_type": "dns_tunnel",
            }

            # DNS tunnels fire queries rapidly but not too suspiciously
            await asyncio.sleep(float(self.rng.uniform(0.5, 5.0)))

    async def generate_exfiltration(
        self,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        total_mb: float = 50.0,
        **kwargs,
    ) -> AsyncIterator[dict]:
        """Generate data exfiltration: large outbound data transfer.

        Args:
            src_ip: Internal compromised host.
            dst_ip: External destination (attacker-controlled).
            total_mb: Total megabytes to exfiltrate.
        """
        src_ip = src_ip or self.rng.choice(self.base._internal_ips)
        dst_ip = dst_ip or self.rng.choice(self.base._external_ips)

        total_bytes = int(total_mb * 1024 * 1024)
        bytes_sent = 0

        # Exfiltration uses HTTPS to blend in, but with abnormally large uploads
        while bytes_sent < total_bytes:
            # Each chunk: large forward payload, small ACK back
            chunk_size = int(self.rng.integers(50_000, 500_000))
            chunk_size = min(chunk_size, total_bytes - bytes_sent)
            bytes_sent += chunk_size

            packets = max(1, chunk_size // 1400)  # ~MTU sized packets
            duration = round(float(packets * self.rng.uniform(0.0005, 0.002)), 4)

            yield {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": int(self.rng.integers(1024, 65535)),
                "dst_port": 443,
                "protocol": "TCP",
                "duration": duration,
                "bytes_fwd": chunk_size,
                "bytes_bwd": int(self.rng.integers(100, 500)),  # ACKs only
                "packets_fwd": packets,
                "packets_bwd": max(1, packets // 3),
                "tcp_flags": {
                    "SYN": 1, "ACK": int(self.rng.integers(10, 100)),
                    "FIN": 1, "RST": 0,
                    "PSH": int(self.rng.integers(5, 50)), "URG": 0,
                    "ECE": 0, "CWR": 0,
                },
                "payload_entropy": round(float(self.rng.uniform(7.0, 7.9)), 4),  # Encrypted/compressed
                "label": "malicious",
                "attack_type": "exfiltration",
            }

            # Short delay between chunks to avoid overwhelming network
            await asyncio.sleep(float(self.rng.uniform(0.1, 2.0)))
