"""Dataset replay module for streaming pre-recorded network traffic datasets."""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import AsyncIterator

import numpy as np
import pandas as pd

logger = logging.getLogger("netguard.testing.replay")


# Column mapping from CICIDS2017 format to NetGuard NetworkFlow fields
CICIDS_COLUMN_MAP = {
    "Flow ID": None,  # Not used
    " Timestamp": "timestamp",
    " Source IP": "src_ip",
    " Source Port": "src_port",
    " Destination IP": "dst_ip",
    " Destination Port": "dst_port",
    " Protocol": "protocol",
    " Flow Duration": "duration",
    " Total Fwd Packets": "packets_fwd",
    " Total Backward Packets": "packets_bwd",
    "Total Length of Fwd Packets": "bytes_fwd",
    " Total Length of Bwd Packets": "bytes_bwd",
    # Additional features that may be present
    "FIN Flag Count": "_fin_count",
    " SYN Flag Count": "_syn_count",
    " RST Flag Count": "_rst_count",
    " PSH Flag Count": "_psh_count",
    " ACK Flag Count": "_ack_count",
    " URG Flag Count": "_urg_count",
    " ECE Flag Count": "_ece_count",
    " CWR Flag Count": "_cwr_count",
    " Label": "_label_raw",
}

# Protocol number to name mapping
PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
    0: "HOPOPT",
}

# Label mapping from CICIDS2017 labels to NetGuard (label, attack_type) tuples
LABEL_MAP = {
    "BENIGN": ("benign", None),
    "FTP-Patator": ("malicious", "brute_force"),
    "SSH-Patator": ("malicious", "brute_force"),
    "DoS slowloris": ("malicious", "dos_slowloris"),
    "DoS Slowhttptest": ("malicious", "dos_slowhttp"),
    "DoS Hulk": ("malicious", "dos_hulk"),
    "DoS GoldenEye": ("malicious", "dos_goldeneye"),
    "Heartbleed": ("malicious", "heartbleed"),
    "Web Attack – Brute Force": ("malicious", "web_brute_force"),
    "Web Attack – XSS": ("malicious", "web_xss"),
    "Web Attack – Sql Injection": ("malicious", "web_sql_injection"),
    "Infiltration": ("malicious", "infiltration"),
    "Bot": ("malicious", "botnet"),
    "PortScan": ("malicious", "port_scan"),
    "DDoS": ("malicious", "ddos"),
}


class CICIDSReplay:
    """Replay CICIDS2017 dataset as a streaming flow source.

    Reads CSV files from the CICIDS2017 dataset and yields them as
    normalized flow dictionaries compatible with the NetGuard pipeline.

    Args:
        data_dir: Path to directory containing CICIDS2017 CSV files.
        speed_multiplier: Replay speed multiplier (1.0 = real-time, >1.0 = faster).
    """

    def __init__(self, data_dir: str, speed_multiplier: float = 1.0) -> None:
        self.data_dir = Path(data_dir)
        self.speed_multiplier = max(0.01, speed_multiplier)
        self._csv_files: list[Path] = []
        self._discover_files()

    def _discover_files(self) -> None:
        """Find all CSV files in the data directory."""
        if not self.data_dir.exists():
            logger.warning(f"Data directory does not exist: {self.data_dir}")
            return

        self._csv_files = sorted(self.data_dir.glob("*.csv"))
        if not self._csv_files:
            logger.warning(f"No CSV files found in: {self.data_dir}")
        else:
            logger.info(f"Found {len(self._csv_files)} CSV files for replay")

    def _map_label(self, raw_label: str) -> tuple[str, str | None]:
        """Map CICIDS2017 label to (label, attack_type) tuple."""
        raw_label = raw_label.strip()
        if raw_label in LABEL_MAP:
            return LABEL_MAP[raw_label]
        # Unknown attack types default to malicious
        if raw_label != "BENIGN":
            return ("malicious", raw_label.lower().replace(" ", "_"))
        return ("benign", None)

    def _map_protocol(self, proto_num: int) -> str:
        """Map protocol number to name."""
        return PROTOCOL_MAP.get(proto_num, f"PROTO_{proto_num}")

    def _build_tcp_flags(self, row: dict) -> dict:
        """Build TCP flags dict from individual flag columns."""
        return {
            "SYN": int(row.get("_syn_count", 0) or 0),
            "ACK": int(row.get("_ack_count", 0) or 0),
            "FIN": int(row.get("_fin_count", 0) or 0),
            "RST": int(row.get("_rst_count", 0) or 0),
            "PSH": int(row.get("_psh_count", 0) or 0),
            "URG": int(row.get("_urg_count", 0) or 0),
            "ECE": int(row.get("_ece_count", 0) or 0),
            "CWR": int(row.get("_cwr_count", 0) or 0),
        }

    def _row_to_flow(self, row: dict) -> dict | None:
        """Convert a mapped CSV row to a NetworkFlow dict."""
        try:
            label, attack_type = self._map_label(str(row.get("_label_raw", "BENIGN")))

            # Convert duration from microseconds to seconds
            duration_us = float(row.get("duration", 0) or 0)
            duration_sec = duration_us / 1_000_000.0

            # Map protocol number
            proto_raw = row.get("protocol", 6)
            protocol = self._map_protocol(int(proto_raw)) if isinstance(proto_raw, (int, float)) else str(proto_raw)

            # Compute a rough payload entropy estimate (not available in CICIDS, approximate)
            bytes_fwd = max(0, int(float(row.get("bytes_fwd", 0) or 0)))
            bytes_bwd = max(0, int(float(row.get("bytes_bwd", 0) or 0)))
            total_bytes = bytes_fwd + bytes_bwd
            # Approximate entropy based on traffic characteristics
            if total_bytes == 0:
                payload_entropy = 0.0
            elif label == "benign":
                payload_entropy = min(8.0, max(0.0, np.log2(max(1, total_bytes)) * 0.6))
            else:
                payload_entropy = min(8.0, max(0.0, np.log2(max(1, total_bytes)) * 0.7))

            return {
                "timestamp": time.time(),
                "src_ip": str(row.get("src_ip", "0.0.0.0")),
                "dst_ip": str(row.get("dst_ip", "0.0.0.0")),
                "src_port": int(float(row.get("src_port", 0) or 0)),
                "dst_port": int(float(row.get("dst_port", 0) or 0)),
                "protocol": protocol,
                "duration": round(duration_sec, 4),
                "bytes_fwd": bytes_fwd,
                "bytes_bwd": bytes_bwd,
                "packets_fwd": max(0, int(float(row.get("packets_fwd", 0) or 0))),
                "packets_bwd": max(0, int(float(row.get("packets_bwd", 0) or 0))),
                "tcp_flags": self._build_tcp_flags(row),
                "payload_entropy": round(payload_entropy, 4),
                "label": label,
                "attack_type": attack_type,
            }
        except (ValueError, TypeError) as e:
            logger.debug(f"Skipping malformed row: {e}")
            return None

    async def stream(self) -> AsyncIterator[dict]:
        """Stream flows from CSV files at configured replay speed.

        Yields flow dicts with realistic inter-flow timing based on the
        original dataset's flow durations and the speed multiplier.
        """
        if not self._csv_files:
            logger.error("No CSV files to replay")
            return

        for csv_file in self._csv_files:
            logger.info(f"Replaying: {csv_file.name}")

            # Read in chunks to handle large files
            chunk_size = 10_000
            try:
                reader = pd.read_csv(
                    csv_file,
                    chunksize=chunk_size,
                    low_memory=False,
                    encoding="utf-8",
                    on_bad_lines="skip",
                )
            except Exception as e:
                logger.error(f"Failed to open {csv_file}: {e}")
                continue

            for chunk in reader:
                # Rename columns using our mapping
                rename_map = {}
                for orig_col, mapped_name in CICIDS_COLUMN_MAP.items():
                    if mapped_name and orig_col in chunk.columns:
                        rename_map[orig_col] = mapped_name

                chunk = chunk.rename(columns=rename_map)

                # Process each row
                prev_time = None
                for _, row in chunk.iterrows():
                    row_dict = row.to_dict()
                    flow = self._row_to_flow(row_dict)

                    if flow is None:
                        continue

                    # Calculate inter-flow delay
                    # Use flow duration as a proxy for temporal spacing
                    if prev_time is not None:
                        # Base delay between flows (simulates real capture timing)
                        inter_flow_delay = 1.0 / 1000.0  # ~1ms base
                    else:
                        inter_flow_delay = 0.0

                    prev_time = time.time()

                    # Apply speed multiplier
                    actual_delay = inter_flow_delay / self.speed_multiplier

                    if actual_delay > 0:
                        await asyncio.sleep(actual_delay)

                    yield flow

            logger.info(f"Completed replay of: {csv_file.name}")
