"""Multi-step attack campaign scenarios for testing detection correlation."""

from __future__ import annotations

import asyncio
import time
from typing import AsyncIterator

from netguard.testing.attacks import AttackGenerator


class AttackScenario:
    """Orchestrates multi-step attack campaigns that simulate real-world threat actors."""

    def __init__(self, attack_gen: AttackGenerator) -> None:
        self.attack_gen = attack_gen
        self.rng = attack_gen.rng

    async def apt_kill_chain(self) -> AsyncIterator[dict]:
        """Simulate an Advanced Persistent Threat kill chain.

        Stages:
        1. Reconnaissance: port scan to identify services
        2. Initial Access: brute force attack on discovered service
        3. Command & Control: establish beacon to external C2
        4. Lateral Movement: pivot to internal hosts
        5. Exfiltration: steal data from compromised network

        Each stage has realistic delays between them to simulate attacker behavior.
        """
        # Select campaign actors
        attacker_ip = self.rng.choice(self.attack_gen.base._external_ips)
        initial_target = self.rng.choice(self.attack_gen.base._internal_ips)
        c2_server = self.rng.choice(self.attack_gen.base._external_ips)

        # Ensure C2 is different from attacker
        while c2_server == attacker_ip:
            c2_server = self.rng.choice(self.attack_gen.base._external_ips)

        # Stage 1: Reconnaissance - Port scan
        async for flow in self.attack_gen.generate_port_scan(
            src_ip=attacker_ip,
            target_ip=initial_target,
            ports=50,
            scan_type="syn",
        ):
            flow["attack_type"] = "apt_recon"
            yield flow

        # Pause between stages (attacker analyzes results)
        await asyncio.sleep(float(self.rng.uniform(10.0, 30.0)))

        # Stage 2: Initial Access - Brute force SSH
        async for flow in self.attack_gen.generate_brute_force(
            target_ip=initial_target,
            service_port=22,
            attempts=30,
            src_ip=attacker_ip,
        ):
            flow["attack_type"] = "apt_brute_force"
            yield flow

        # Pause (attacker gained access, setting up persistence)
        await asyncio.sleep(float(self.rng.uniform(30.0, 120.0)))

        # Stage 3: C2 Beacon - Establish command and control
        beacon_count = 10  # Limited beacons during scenario
        async for flow in self.attack_gen.generate_c2_beacon(
            infected_ip=initial_target,
            c2_server=c2_server,
            beacon_count=beacon_count,
            interval_sec=30.0,
        ):
            flow["attack_type"] = "apt_c2"
            yield flow

        # Pause (attacker received instructions)
        await asyncio.sleep(float(self.rng.uniform(5.0, 20.0)))

        # Stage 4: Lateral Movement - Pivot to other internal hosts
        async for flow in self.attack_gen.generate_lateral_movement(
            compromised_ip=initial_target,
            targets=3,
        ):
            flow["attack_type"] = "apt_lateral"
            yield flow

        # Pause (attacker found valuable data)
        await asyncio.sleep(float(self.rng.uniform(10.0, 60.0)))

        # Stage 5: Exfiltration - Steal data via C2 channel
        async for flow in self.attack_gen.generate_exfiltration(
            src_ip=initial_target,
            dst_ip=c2_server,
            total_mb=10.0,
        ):
            flow["attack_type"] = "apt_exfiltration"
            yield flow

    async def botnet_recruitment(self) -> AsyncIterator[dict]:
        """Simulate a botnet recruitment and activation campaign.

        Stages:
        1. Exploit: Initial exploitation of vulnerable service
        2. C2 Registration: New bot registers with botnet C2
        3. Beacon: Regular check-ins with C2 infrastructure
        4. Scanning: Infected host scans for more vulnerable hosts
        5. Second Infection: Spread to discovered vulnerable host
        6. DDoS: Botnet activation for DDoS attack

        Simulates the lifecycle of a bot from infection through activation.
        """
        # Campaign actors
        bot_ip = self.rng.choice(self.attack_gen.base._internal_ips)
        c2_server = self.rng.choice(self.attack_gen.base._external_ips)
        exploit_source = self.rng.choice(self.attack_gen.base._external_ips)

        # Ensure distinct IPs
        while c2_server == exploit_source:
            c2_server = self.rng.choice(self.attack_gen.base._external_ips)

        # Stage 1: Exploit - Initial infection via vulnerable service
        exploit_port = int(self.rng.choice([80, 443, 8080, 445]))
        yield {
            "timestamp": time.time(),
            "src_ip": exploit_source,
            "dst_ip": bot_ip,
            "src_port": int(self.rng.integers(1024, 65535)),
            "dst_port": exploit_port,
            "protocol": "TCP",
            "duration": round(float(self.rng.uniform(1.0, 5.0)), 4),
            "bytes_fwd": int(self.rng.integers(2000, 10000)),  # Exploit payload
            "bytes_bwd": int(self.rng.integers(500, 2000)),    # Shellcode response
            "packets_fwd": int(self.rng.integers(5, 20)),
            "packets_bwd": int(self.rng.integers(3, 10)),
            "tcp_flags": {
                "SYN": 1, "ACK": int(self.rng.integers(5, 15)),
                "FIN": 0, "RST": 0,
                "PSH": int(self.rng.integers(3, 10)), "URG": 1,
                "ECE": 0, "CWR": 0,
            },
            "payload_entropy": round(float(self.rng.uniform(6.5, 7.8)), 4),
            "label": "malicious",
            "attack_type": "botnet_exploit",
        }

        # Brief pause (malware installing)
        await asyncio.sleep(float(self.rng.uniform(2.0, 10.0)))

        # Stage 2: C2 Registration - Bot phones home to register
        yield {
            "timestamp": time.time(),
            "src_ip": bot_ip,
            "dst_ip": c2_server,
            "src_port": int(self.rng.integers(1024, 65535)),
            "dst_port": 443,
            "protocol": "TCP",
            "duration": round(float(self.rng.uniform(0.5, 2.0)), 4),
            "bytes_fwd": int(self.rng.integers(200, 800)),   # Registration data
            "bytes_bwd": int(self.rng.integers(100, 500)),   # Config/instructions
            "packets_fwd": int(self.rng.integers(3, 8)),
            "packets_bwd": int(self.rng.integers(2, 6)),
            "tcp_flags": {
                "SYN": 1, "ACK": int(self.rng.integers(4, 10)),
                "FIN": 1, "RST": 0,
                "PSH": int(self.rng.integers(2, 5)), "URG": 0,
                "ECE": 0, "CWR": 0,
            },
            "payload_entropy": round(float(self.rng.uniform(6.8, 7.5)), 4),
            "label": "malicious",
            "attack_type": "botnet_registration",
        }

        # Pause (waiting for instructions)
        await asyncio.sleep(float(self.rng.uniform(30.0, 60.0)))

        # Stage 3: Beacon - Regular check-ins
        async for flow in self.attack_gen.generate_c2_beacon(
            infected_ip=bot_ip,
            c2_server=c2_server,
            beacon_count=5,
            interval_sec=20.0,
        ):
            flow["attack_type"] = "botnet_beacon"
            yield flow

        # Stage 4: Scanning - Scan internal network for propagation
        second_target = self.rng.choice(
            [ip for ip in self.attack_gen.base._internal_ips if ip != bot_ip]
        )
        async for flow in self.attack_gen.generate_port_scan(
            src_ip=bot_ip,
            target_ip=second_target,
            ports=20,
            scan_type="syn",
        ):
            flow["attack_type"] = "botnet_scan"
            yield flow

        # Pause (found vulnerable target)
        await asyncio.sleep(float(self.rng.uniform(5.0, 15.0)))

        # Stage 5: Second Infection - Spread to new host
        yield {
            "timestamp": time.time(),
            "src_ip": bot_ip,
            "dst_ip": second_target,
            "src_port": int(self.rng.integers(1024, 65535)),
            "dst_port": 445,  # SMB exploit
            "protocol": "TCP",
            "duration": round(float(self.rng.uniform(1.0, 4.0)), 4),
            "bytes_fwd": int(self.rng.integers(3000, 15000)),  # Worm payload
            "bytes_bwd": int(self.rng.integers(500, 2000)),
            "packets_fwd": int(self.rng.integers(8, 30)),
            "packets_bwd": int(self.rng.integers(4, 15)),
            "tcp_flags": {
                "SYN": 1, "ACK": int(self.rng.integers(8, 25)),
                "FIN": 0, "RST": 0,
                "PSH": int(self.rng.integers(5, 15)), "URG": 1,
                "ECE": 0, "CWR": 0,
            },
            "payload_entropy": round(float(self.rng.uniform(6.5, 7.8)), 4),
            "label": "malicious",
            "attack_type": "botnet_propagation",
        }

        # Pause (bot receives DDoS command)
        await asyncio.sleep(float(self.rng.uniform(10.0, 30.0)))

        # Stage 6: DDoS - Botnet activation (SYN flood from recruited bots)
        ddos_target = self.rng.choice(self.attack_gen.base._external_ips)
        async for flow in self.attack_gen.generate_syn_flood(
            target_ip=ddos_target,
            target_port=80,
            duration_sec=10.0,
            rate=500,
        ):
            flow["src_ip"] = bot_ip  # Overwrite spoofed IP with actual bot IP
            flow["attack_type"] = "botnet_ddos"
            yield flow
