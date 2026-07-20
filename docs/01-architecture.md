# System Architecture

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              NETWORK LAYER (Data Sources)                             │
│                                                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │ TAP/SPAN │  │ NetFlow  │  │  Zeek    │  │Suricata  │  │  Firewall / Endpoint │  │
│  │ Port     │  │ v9/IPFIX │  │  Sensor  │  │  IDS     │  │  Logs                │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────────┬───────────┘  │
└───────┼──────────────┼──────────────┼──────────────┼──────────────────┼──────────────┘
        └──────────────┴──────────────┴──────────────┴──────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              INGESTION LAYER                                         │
│                                                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────────┐  │
│  │                         Apache Kafka Cluster                                   │  │
│  │                                                                               │  │
│  │  Topics:                                                                      │  │
│  │  • raw-packets (partitions:6, retention:1h)                                   │  │
│  │  • parsed-flows (partitions:12, retention:24h)                                │  │
│  │  • enriched-flows (partitions:12, retention:7d)                               │  │
│  │  • alerts (partitions:3, retention:30d)                                       │  │
│  │  • threat-intel-updates (partitions:1)                                        │  │
│  │  • model-feedback (partitions:3)                                              │  │
│  │  • system-metrics (partitions:3)                                              │  │
│  └───────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          STREAM PROCESSING LAYER                                     │
│                                                                                      │
│  ┌─────────────────┐  ┌──────────────────────┐  ┌──────────────────────────────┐   │
│  │  Flow Parser    │  │  Feature Extractor   │  │  Windowed Aggregator         │   │
│  │  Agent          │  │  Agent               │  │  Agent                       │   │
│  │                 │  │                      │  │                              │   │
│  │ • Parse raw     │  │ • Per-flow features  │  │ • 1min / 5min / 1hr windows  │   │
│  │   packets/logs  │  │ • Entropy calc       │  │ • Per-IP rolling aggregates  │   │
│  │ • Normalize     │  │ • Flag analysis      │  │ • Peer-group statistics      │   │
│  │ • Validate      │  │ • Byte ratios        │  │ • Store results in Redis     │   │
│  └────────┬────────┘  └──────────┬───────────┘  └──────────────┬───────────────┘   │
│           │                      │                              │                    │
│           ▼                      ▼                              ▼                    │
│  ┌──────────────────────────────────────────────────────────────────────────────┐   │
│  │                          Scoring Engine Agent                                 │   │
│  │                                                                              │   │
│  │  features + context ──▶ [Online Model]  ──┐                                  │   │
│  │                         [Autoencoder]   ──┼──▶ Ensemble ──▶ Threshold ──▶ ?  │   │
│  │                         [XGBoost]       ──┤                                  │   │
│  │                         [Rules Engine]  ──┤                                  │   │
│  │                         [Threat Intel]  ──┘                                  │   │
│  └──────────────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────────────┘
          │                           │                              │
          ▼                           ▼                              ▼
┌────────────────────┐  ┌──────────────────────┐  ┌────────────────────────────────┐
│  FEATURE STORE     │  │    ML MODEL LAYER    │  │    DETECTION & ALERTING        │
│                    │  │                      │  │                                │
│  Redis Cluster     │  │  Model Registry      │  │  Alert Correlator              │
│  • IP Profiles     │  │  (MLflow)            │  │  Alert Deduplicator            │
│  • Rolling Windows │  │                      │  │  Severity Scorer               │
│  • Threat Intel    │  │  • Online models     │  │  Alert Router                  │
│  • Score History   │  │  • Batch models      │  │  • Slack / PagerDuty           │
│  • Dedup Cache     │  │  • Ensemble config   │  │  • Webhook / SIEM             │
│                    │  │  • A/B testing        │  │  • Email / File               │
└────────────────────┘  └──────────────────────┘  └────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              STORAGE LAYER                                            │
│                                                                                      │
│  ┌────────────────────────┐  ┌──────────────────────┐  ┌────────────────────────┐  │
│  │   TimescaleDB          │  │   PostgreSQL          │  │   Object Storage       │  │
│  │                        │  │                       │  │   (S3/Minio)           │  │
│  │  • enriched_flows      │  │  • alerts             │  │                        │  │
│  │  • flow_aggregates     │  │  • incidents          │  │  • model artifacts     │  │
│  │                        │  │  • analyst_feedback   │  │  • training datasets   │  │
│  │  Retention:            │  │  • threat_intel_iocs  │  │  • pcap archives       │  │
│  │  7d raw, 90d agg      │  │  • model_versions     │  │                        │  │
│  └────────────────────────┘  └──────────────────────┘  └────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          OBSERVABILITY & API LAYER                                    │
│                                                                                      │
│  ┌──────────────────────────────┐  ┌─────────────────────────────────────────────┐  │
│  │       FastAPI Server         │  │       Monitoring Stack                       │  │
│  │                              │  │                                             │  │
│  │  POST /api/v1/score          │  │  Prometheus → Grafana                       │  │
│  │  GET  /api/v1/alerts         │  │  Alertmanager (system health)               │  │
│  │  POST /api/v1/feedback       │  │                                             │  │
│  │  GET  /api/v1/models/status  │  │  Dashboards:                                │  │
│  │  GET  /api/v1/stats          │  │  • Traffic Overview                         │  │
│  │  PUT  /api/v1/config         │  │  • Alert Feed                               │  │
│  │                              │  │  • Model Performance                        │  │
│  └──────────────────────────────┘  │  • System Health                            │  │
│                                    └─────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Single Event Lifecycle

```
Time ──────────────────────────────────────────────────────────────────────────────▶

 0ms        5ms           15ms          25ms         40ms         55ms       70ms
  │          │              │             │            │            │          │
  ▼          ▼              ▼             ▼            ▼            ▼          ▼
┌─────┐   ┌──────┐    ┌─────────┐   ┌────────┐  ┌─────────┐  ┌───────┐  ┌───────┐
│Event│──▶│Kafka │───▶│ Parse & │──▶│ Enrich │─▶│ Score   │─▶│Thresh │─▶│ Alert │
│     │   │ingest│    │normalize│   │features│  │ensemble │  │check  │  │route  │
└─────┘   └──────┘    └─────────┘   └────────┘  └─────────┘  └───────┘  └───────┘
                                         │            │                       │
                                         ▼            ▼                       ▼
                                    ┌─────────┐ ┌──────────┐           ┌──────────┐
                                    │ Redis   │ │ Online   │           │ Slack/   │
                                    │ update  │ │ model    │           │ SIEM/    │
                                    │ profile │ │ update   │           │ webhook  │
                                    └─────────┘ └──────────┘           └──────────┘
```

## Component Responsibilities

### Ingestion Layer
- **Kafka**: Message broker, decouples producers from consumers, provides replay capability
- **Adapters**: Normalize different data sources into a common `NetworkFlow` schema

### Processing Layer
- **Flow Parser**: Raw data → structured flow records with validation
- **Feature Extractor**: Per-flow features (entropy, ratios, flag counts)
- **Window Aggregator**: Rolling statistics per entity (IP, subnet, port)
- **Scoring Engine**: Orchestrates ensemble scoring pipeline

### ML Layer
- **Online Models** (River): Half-Space Trees, Isolation Forest — learn incrementally
- **Batch Models** (PyTorch/XGBoost): Autoencoder + classifier — retrained nightly
- **Ensemble**: Weighted combination of all model scores
- **Model Registry**: Version control, A/B testing, rollback

### Detection Layer
- **Rules Engine**: Signature-based detection (port scan heuristics, flood thresholds)
- **Threat Intel**: IOC matching (known malicious IPs, domains, hashes)
- **Alert Correlator**: Group related alerts into incidents (kill-chain detection)
- **Alert Router**: Send to appropriate channels based on severity

### Storage Layer
- **Redis**: Hot data — real-time features, profiles, caches (sub-ms reads)
- **TimescaleDB**: Warm data — recent flows and aggregates (time-series optimized)
- **PostgreSQL**: Cold data — alerts, incidents, config, feedback
- **Object Storage**: Archive — models, datasets, pcap files

## Data Schema

### NetworkFlow (Core Data Model)

```python
@dataclass
class NetworkFlow:
    timestamp: float          # Unix timestamp
    src_ip: str              # Source IP address
    dst_ip: str              # Destination IP address
    src_port: int            # Source port
    dst_port: int            # Destination port
    protocol: str            # TCP, UDP, ICMP
    duration: float          # Connection duration (seconds)
    bytes_fwd: int           # Bytes source → destination
    bytes_bwd: int           # Bytes destination → source
    packets_fwd: int         # Packets source → destination
    packets_bwd: int         # Packets destination → source
    tcp_flags: dict          # {SYN, ACK, FIN, RST, PSH, URG}
    payload_entropy: float   # Shannon entropy of payload (0-8)
```

### Alert (Output Data Model)

```python
@dataclass
class Alert:
    id: str                  # Unique alert ID
    timestamp: float         # When detected
    severity: str            # critical, high, medium, low, info
    attack_type: str         # port_scan, ddos, brute_force, etc.
    confidence: float        # 0.0 - 1.0
    src_ip: str
    dst_ip: str
    description: str         # Human-readable summary
    evidence: dict           # Supporting data (scores, features, rules matched)
    recommended_action: str  # Suggested response
```

## Communication Patterns

| Pattern | Where Used | Why |
|---------|-----------|-----|
| Pub/Sub (Kafka) | Between all layers | Decoupling, replay, scaling |
| Request/Response (HTTP) | API layer, external integrations | Standard REST interface |
| Fire-and-forget (Redis) | Feature updates | Speed, eventual consistency OK |
| Streaming (SSE/WebSocket) | Alert feed to dashboard | Real-time push to UI |
| Batch (Cron) | Model retraining, IOC updates | Heavy computation, periodic |
