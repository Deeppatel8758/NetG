# NetGuard - Real-Time Network Intrusion Detection System

## Project Overview

NetGuard is an open-source, plug-and-play real-time network intrusion detection system (NIDS) that uses stream processing and online machine learning to detect network attacks with adaptive thresholds.

## Problem Statement

Traditional intrusion detection systems are:
- Rule-based only (miss novel attacks)
- Batch-processed (detect threats hours/days later)
- Hard to deploy (require deep expertise)
- Not adaptive (static thresholds cause alert fatigue)

NetGuard solves this by combining:
- **Real-time stream processing** (sub-100ms detection latency)
- **Online ML models** (learn and adapt without retraining)
- **Ensemble scoring** (multiple models reduce false positives)
- **Adaptive thresholds** (auto-adjust to network patterns)
- **Plug-and-play design** (pip install, configure, run)

## Attack Types Detected

| Category | Attacks | Detection Method |
|----------|---------|-----------------|
| Reconnaissance | Port scan, host sweep, OS fingerprinting | High unique dst_ports, SYN-only flags, short duration |
| DDoS | SYN flood, UDP flood, amplification | Sudden packet spike, uniform packet size |
| Brute Force | SSH/RDP/FTP login attempts | Repeated auth-port connections, high failure rate |
| Lateral Movement | Internal pivoting, pass-the-hash | Unusual internal-to-internal flows, new src-dst pairs |
| C2 Communication | Beaconing, DNS tunneling | Periodic patterns, high DNS entropy |
| Data Exfiltration | Large outbound transfers | Abnormal bytes_out ratio, rare external destinations |

## Design Goals

1. **Open Source & Community-Driven** - Apache 2.0 license, extensible plugin system
2. **Plug-and-Play** - Working in under 5 minutes with `netguard demo`
3. **Production-Ready** - Handles 10K+ flows/sec on modest hardware
4. **Adaptive** - Models learn continuously, thresholds auto-adjust
5. **Extensible** - Custom adapters, models, and outputs via clean interfaces
6. **Observable** - Built-in metrics, dashboards, and health monitoring

## Quick Start (Target User Experience)

```bash
# Install
pip install netguard

# Run demo with synthetic data (zero external dependencies)
netguard demo

# Run with your Kafka stream
netguard run --config netguard.yaml

# Replay a dataset for testing
netguard replay --input ./data/cicids2017/ --format cicids --speed 10x
```

## Repository Structure

```
netguard/
├── src/netguard/          # Core library (pip-installable)
│   ├── core/              # Engine, pipeline, config
│   ├── adapters/          # Input plugins (Kafka, pcap, CSV, etc.)
│   ├── features/          # Feature extraction and store
│   ├── models/            # ML models (online, batch, ensemble)
│   ├── threshold/         # Adaptive threshold strategies
│   ├── detection/         # Rules engine, threat intel, correlation
│   ├── outputs/           # Alert sinks (Slack, webhook, SIEM, etc.)
│   ├── api/               # FastAPI server
│   └── testing/           # Built-in traffic generators
├── examples/              # Usage examples
├── configs/               # Pre-built configuration files
├── dashboards/            # Grafana dashboard JSON
├── tests/                 # Unit + integration tests
├── notebooks/             # EDA and model analysis
├── scripts/               # Setup and utility scripts
└── docs/                  # This documentation
```

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Language | Python 3.11+ | ML ecosystem, async support, developer adoption |
| Package Manager | uv | Fast, modern, reliable |
| Streaming | Apache Kafka + Faust | Python-native stream processing |
| Feature Store | Redis | Sub-ms reads for real-time features |
| Online ML | River | Incremental learning, no retrain needed |
| Batch ML | PyTorch + XGBoost | Autoencoder + classifier |
| API | FastAPI | Async, fast, auto-docs |
| Storage | TimescaleDB + PostgreSQL | Time-series + relational |
| Monitoring | Prometheus + Grafana | Industry standard observability |
| Containers | Docker + Docker Compose | Easy deployment |
| Model Registry | MLflow | Version, track, deploy models |
