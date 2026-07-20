# Resource Requirements

## Deployment Tiers

### Tier 1: Development / Demo (Single Machine)

**Use case:** Local development, demo, testing with synthetic data, CI/CD

```
┌──────────────────────────────────────────────────────┐
│              Single Machine (Docker Compose)           │
│                                                       │
│  CPU: 4-8 cores | RAM: 16 GB | Disk: 50 GB SSD      │
│                                                       │
│  ┌──────────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌───────┐ │
│  │Kafka (1) │ │Faust │ │Redis │ │PG/TS │ │Grafana│ │
│  │1 broker  │ │(2w)  │ │(1)   │ │(1)   │ │       │ │
│  └──────────┘ └──────┘ └──────┘ └──────┘ └───────┘ │
└──────────────────────────────────────────────────────┘
```

| Component | CPU | RAM | Disk |
|-----------|-----|-----|------|
| Kafka (1 broker) | 1 core | 2 GB | 10 GB |
| Faust (2 workers) | 2 cores | 2 GB | - |
| Redis | 0.5 core | 1 GB | - |
| PostgreSQL + TimescaleDB | 1 core | 2 GB | 20 GB |
| Grafana | 0.25 core | 512 MB | 1 GB |
| Prometheus | 0.5 core | 1 GB | 5 GB |
| FastAPI (2 workers) | 1 core | 1 GB | - |
| ML Models (in workers) | (shared) | (shared) | - |
| OS + overhead | 1 core | 3 GB | 10 GB |
| **TOTAL** | **~8 cores** | **~13 GB** | **~50 GB** |

| Metric | Value |
|--------|-------|
| Throughput | ~1,000 flows/sec |
| Detection Latency | < 200ms |
| Monthly cost (cloud) | ~$120 (AWS t3.2xlarge) |
| Monthly cost (local) | $0 |

---

### Tier 2: Small Production (Small/Medium Network)

**Use case:** 1-5 Gbps network, single office/campus, 500-2000 hosts

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌───────────────────┐  │
│  │   Node 1: Kafka      │  │  Node 2: Processing  │  │ Node 3: Storage   │  │
│  │  4 CPU / 8 GB RAM    │  │  8 CPU / 16 GB RAM   │  │  4 CPU / 32 GB    │  │
│  │  100 GB SSD          │  │  50 GB SSD           │  │  500 GB SSD       │  │
│  └──────────────────────┘  └──────────────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Node | Instance Type (AWS) | Monthly Cost |
|------|-------------------|--------------|
| Kafka | c5.xlarge (4 vCPU, 8 GB) + 100 GB gp3 | ~$130 |
| Processing | c5.2xlarge (8 vCPU, 16 GB) + 50 GB gp3 | ~$250 |
| Storage | r5.xlarge (4 vCPU, 32 GB) + 500 GB gp3 | ~$300 |
| GPU (optional) | g4dn.xlarge (T4) | ~$380 |
| Network transfer | ~500 GB/month | ~$45 |
| **Total (no GPU)** | | **~$725/month** |
| **Total (with GPU)** | | **~$1,100/month** |

| Metric | Value |
|--------|-------|
| Throughput | ~10,000 flows/sec |
| Detection Latency | < 100ms (p95) |
| Hosts Monitored | 500 - 2,000 |
| Network Bandwidth | 1-5 Gbps |

---

### Tier 3: Enterprise Production (Large Network)

**Use case:** 10-40 Gbps network, multiple sites, 5,000-50,000 hosts, SOC team

| Component | Instances | Spec per Instance | Monthly Cost |
|-----------|-----------|-------------------|--------------|
| Kafka brokers | 5 | r5.xlarge, 1TB gp3 | ~$1,800 |
| Faust workers | 12 pods | 2 CPU, 4 GB each (on 3 c5.4xlarge) | ~$1,500 |
| FastAPI | 6 pods | 2 CPU, 4 GB each (shared nodes) | (included) |
| Redis Cluster | 6 (3M + 3R) | r6g.xlarge, 32 GB | ~$1,400 |
| TimescaleDB | 3 (1P + 2R) | r5.2xlarge, 64 GB, 2TB NVMe | ~$2,400 |
| PostgreSQL | 3 (1P + 2R) | r5.xlarge, 32 GB, 200 GB | ~$900 |
| GPU nodes | 2 | g4dn.xlarge (T4) | ~$760 |
| Monitoring | 2 | m5.xlarge | ~$560 |
| Load Balancer + Transfer | - | ALB + 2TB egress | ~$500 |
| S3 Storage | - | 5 TB | ~$115 |
| **Total** | | | **~$9,900/month** |

| Metric | Value |
|--------|-------|
| Throughput | ~100,000 flows/sec |
| Detection Latency | < 100ms (p95) |
| Hosts Monitored | 5,000 - 50,000 |
| Network Bandwidth | 10-40 Gbps |
| Availability | 99.9% |

---

## Memory Budget Breakdown (Tier 2 Reference - 16 GB Processing Node)

| Component | Allocation | Detail |
|-----------|-----------|--------|
| Faust Workers (4 processes) | | |
| - Python runtime | 600 MB | 4 x 150 MB |
| - Online models (River) | 800 MB | 4 x 200 MB |
| - XGBoost model | 400 MB | 4 x 100 MB |
| - Autoencoder (PyTorch) | 1,200 MB | 4 x 300 MB |
| - Feature buffers | 400 MB | 4 x 100 MB |
| - Kafka consumer buffers | 256 MB | 4 x 64 MB |
| **Faust subtotal** | **3,656 MB** | |
| Redis | | |
| - IP profiles (2000 hosts) | 200 MB | 2000 x 50 fields |
| - Sliding windows | 100 MB | score history |
| - Threat intel (100K IOCs) | 150 MB | IP/domain sets |
| - Dedup cache | 50 MB | alert dedup |
| - Overhead | 100 MB | |
| **Redis subtotal** | **600 MB** | |
| FastAPI (4 workers) | 600 MB | 4 x 150 MB |
| Prometheus (15d retention) | 2,000 MB | TSDB + WAL |
| OS + headroom | 2,000 MB | |
| **TOTAL** | **~8,856 MB** | |
| **Available** | **16,000 MB** | |
| **Headroom** | **~7,100 MB** | |

---

## Disk I/O Requirements

| Component | Read IOPS | Write IOPS | Throughput | Required Disk |
|-----------|-----------|------------|------------|---------------|
| Kafka broker | 500 | 3,000 | 200 MB/s write | NVMe/gp3 SSD |
| TimescaleDB | 2,000 | 5,000 | 300 MB/s write | NVMe SSD |
| Redis (AOF mode) | - | 500 | 10 MB/s | Any SSD |
| Prometheus | 200 | 1,000 | 50 MB/s | SSD |

---

## Storage Growth Estimates

### At 10,000 flows/sec (Tier 2)

| Data | Row Size | Rows/Day | Daily Growth | With Compression |
|------|----------|----------|--------------|-----------------|
| Raw flows (Kafka) | 500 bytes | 864M | 400 GB | 24h retention = 400 GB max |
| Enriched flows (TimescaleDB) | 500 bytes | 864M | 400 GB | ~100 GB (LZ4) |
| Aggregates 1-min | 200 bytes | 2.88M | 550 MB | ~150 MB |
| Aggregates 1-hr | 200 bytes | 48K | 9 MB | ~3 MB |
| Alerts | 2 KB | ~5,000 | 10 MB | ~5 MB |

**With recommended retention policies:**
| Store | Retention | Max Disk Usage |
|-------|-----------|---------------|
| Kafka (raw) | 1 hour | 40 GB |
| Kafka (parsed) | 24 hours | 400 GB |
| TimescaleDB (flows) | 7 days | 700 GB compressed |
| TimescaleDB (aggs) | 90 days | 15 GB |
| PostgreSQL (alerts) | Indefinite | Grows ~150 MB/month |
| Object Storage (models) | Indefinite | ~5 GB |

---

## Network Bandwidth Math

```
Monitored Link    → Packets/sec    → Flows/sec (estimate)    → Recommended Tier
─────────────────────────────────────────────────────────────────────────────────
  100 Mbps        →  ~25,000 pps   →    250 -   500 flows/s  → Tier 1
    1 Gbps        → ~250,000 pps   →  2,500 - 5,000 flows/s  → Tier 2
   10 Gbps        → ~2.5M pps      → 25,000 - 50,000 flows/s → Tier 3
   40 Gbps        → ~10M pps       → 100K - 200K flows/s     → Tier 3 (maxed)

Note: Flow ratio ≈ 50-100 packets per flow (typical enterprise traffic)
```

---

## Latency Budget

| Stage | Time (ms) | Cumulative |
|-------|-----------|-----------|
| Kafka produce | 5 | 5 |
| Kafka → Faust consume | 10 | 15 |
| Parse & normalize | 2 | 17 |
| Feature extraction | 5 | 22 |
| Redis read (IP profile) | 3 | 25 |
| Redis write (update profile) | 3 | 28 |
| Online model score | 5 | 33 |
| Autoencoder inference | 15 (CPU) / 3 (GPU) | 48 / 36 |
| XGBoost inference | 3 | 51 / 39 |
| Rules engine | 2 | 53 / 41 |
| Ensemble + threshold | 1 | 54 / 42 |
| Alert correlation | 3 | 57 / 45 |
| Kafka produce (alert) | 5 | 62 / 50 |
| Buffer + overhead | 10 | 72 / 60 |
| **Total (CPU)** | **~72ms** | p50: ~50ms, p95: ~90ms |
| **Total (GPU)** | **~60ms** | p50: ~40ms, p95: ~75ms |

---

## Scaling Rules

| Condition | Threshold | Action |
|-----------|-----------|--------|
| Kafka consumer lag | > 10K messages for 2 min | Add Faust workers (+1 per 5K lag) |
| FastAPI p95 latency | > 50ms | Add FastAPI pods (+2) |
| Redis memory | > 80% maxmemory | Increase maxmemory or add node |
| TimescaleDB disk | > 70% capacity | Reduce retention or expand disk |
| Kafka disk | > 60% capacity | Reduce retention or add broker |
| Faust CPU | > 80% sustained 5 min | Scale up instance or add workers |
| Throughput | > 50K flows/sec | Add Kafka partitions + workers |

---

## Minimum Hardware for Each Tier

### Tier 1 - Your Laptop
- **Minimum**: 4 cores, 8 GB RAM, 30 GB free disk
- **Recommended**: 8 cores, 16 GB RAM, 50 GB SSD
- **OS**: Linux (native) / macOS / Windows (WSL2)

### Tier 2 - Small Server
- **Minimum**: 16 cores total, 48 GB RAM, 1 TB SSD (across 3 nodes)
- **Recommended**: 24 cores total, 64 GB RAM, 2 TB NVMe
- **Network**: 1 Gbps between nodes minimum

### Tier 3 - Kubernetes Cluster
- **Minimum**: 10 nodes, 100 cores, 500 GB RAM, 10 TB storage
- **Recommended**: 15+ nodes, 150 cores, 750 GB RAM, 20 TB NVMe
- **Network**: 10 Gbps between nodes, dedicated storage network
