# Implementation Phases

## Phase Overview

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                           IMPLEMENTATION TIMELINE                                      │
├──────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                       │
│  Phase 1: Foundation          ████████░░░░░░░░░░░░░░░░░░░░░░░░░░  Week 1-2           │
│  Phase 2: Feature Engineering ░░░░░░░░████████░░░░░░░░░░░░░░░░░░  Week 3-4           │
│  Phase 3: ML Models           ░░░░░░░░░░░░░░░░████████░░░░░░░░░░  Week 5-6           │
│  Phase 4: Detection & Alerts  ░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░  Week 7             │
│  Phase 5: API & Dashboard     ░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░  Week 8             │
│  Phase 6: Polish & Release    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██  Week 9-10          │
│                                                                                       │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Foundation & Infrastructure (Week 1-2)

### Goal
Get the basic pipeline running: data flows from source → Kafka → consumer → stdout. Prove the streaming architecture works end-to-end.

### Tasks

```
[ ] 1.1 Project Setup
    [ ] Initialize Python project with uv (pyproject.toml)
    [ ] Set up project structure (src/netguard/...)
    [ ] Configure ruff (linting), mypy (types), pytest
    [ ] Set up pre-commit hooks
    [ ] Create initial README.md with project description
    [ ] Choose and add LICENSE (Apache 2.0 recommended)

[ ] 1.2 Docker Infrastructure
    [ ] Create docker-compose.yml with:
        - Kafka (single broker) + Zookeeper
        - Redis (single instance)
        - PostgreSQL + TimescaleDB extension
        - Grafana (pre-configured)
        - Prometheus
    [ ] Create setup script (scripts/setup_kafka_topics.sh)
    [ ] Verify all services start and communicate
    [ ] Add health check endpoints for each service

[ ] 1.3 Configuration System
    [ ] Implement Pydantic settings model (src/netguard/core/config.py)
    [ ] Support YAML config file loading
    [ ] Support environment variable overrides
    [ ] Create default.yaml with sensible defaults
    [ ] Add config validation with clear error messages

[ ] 1.4 Synthetic Traffic Generator
    [ ] Implement TrafficProfile dataclass
    [ ] Implement NetworkTrafficGenerator (normal flows)
    [ ] Implement time-of-day rate patterns
    [ ] Implement host role assignment (workstation, server, etc.)
    [ ] Add CLI command: netguard generate --profile normal --output stdout

[ ] 1.5 Kafka Integration
    [ ] Implement KafkaAdapter (consumer) — read from topic, yield NetworkFlow
    [ ] Implement Kafka producer utility — write generated flows to topic
    [ ] Create basic Faust app skeleton (src/netguard/processing/stream_app.py)
    [ ] Verify: generator → Kafka → Faust consumer → log to stdout

[ ] 1.6 Base Classes & Interfaces
    [ ] Define SourceAdapter ABC
    [ ] Define NetworkFlow dataclass
    [ ] Define AnomalyModel ABC
    [ ] Define OutputSink ABC
    [ ] Define Alert dataclass
```

### Deliverable
- `docker compose up` starts all infrastructure
- `netguard generate` produces realistic traffic into Kafka
- Faust app consumes and logs events
- All base classes defined and documented

### Verification
```bash
docker compose up -d
netguard generate --profile normal --rate 100 --output kafka://localhost:9092/raw-flows &
# In another terminal:
netguard run --config configs/default.yaml
# Should see: "[INFO] Consumed flow: 10.0.1.23 → 203.0.113.50:443 TCP ..."
```

---

## Phase 2: Feature Engineering (Week 3-4)

### Goal
Extract meaningful features from raw flows in real-time. Build the Redis-backed feature store for rolling aggregates.

### Tasks

```
[ ] 2.1 Per-Flow Feature Extraction
    [ ] Implement flow_features.py:
        - bytes_per_packet (fwd/bwd)
        - fwd_bwd_ratio (bytes and packets)
        - tcp_flag_counts and ratios
        - payload_entropy normalization
        - duration bucketization
        - protocol one-hot encoding
        - dst_port categorization (well-known/registered/ephemeral)
    [ ] Unit tests with known inputs → expected outputs

[ ] 2.2 Redis Feature Store
    [ ] Implement Redis connection manager (connection pooling)
    [ ] Design Redis key schema:
        - ip_profile:{ip} (Hash) — per-IP aggregates
        - window:{ip}:{window_size} (Sorted Set) — time-series data
        - threshold:scores (Sorted Set) — score history
    [ ] Implement atomic increment operations
    [ ] Add TTL-based expiration (auto-cleanup)
    [ ] Implement memory-based fallback (for zero-dependency mode)

[ ] 2.3 Windowed Aggregations (1min, 5min, 1hr)
    [ ] Implement sliding window counter using Redis sorted sets
    [ ] Per-IP metrics:
        - unique_dst_ips (HyperLogLog for memory efficiency)
        - unique_dst_ports (HyperLogLog)
        - total_bytes_out / total_bytes_in (atomic counter)
        - connection_count (counter)
        - failed_connections (counter)
        - avg_duration (running mean)
        - protocol_entropy (distribution tracking)
    [ ] Window rollover logic (old entries expire automatically)
    [ ] Unit tests: feed known sequence → verify aggregates

[ ] 2.4 IP Profiling
    [ ] Implement IP profiler that maintains behavioral baseline per host
    [ ] Track: typical ports used, typical destinations, activity hours
    [ ] Detect "new behavior": first-time dst_ip, first-time port, etc.
    [ ] Implement peer-group assignment (by subnet + role)

[ ] 2.5 Peer-Group Features
    [ ] Compute per-subnet averages (bytes, connections, ports)
    [ ] Z-score calculation: how far is this host from its peers?
    [ ] Update peer-group stats periodically (every 5 min)
    [ ] Handle cold-start: new IPs get default profile until data accumulates

[ ] 2.6 Integration with Stream Processor
    [ ] Wire feature extraction into Faust pipeline:
        raw-flows → parse → extract features → enrich with Redis → enriched-flows
    [ ] Ensure feature computation adds < 10ms latency
    [ ] Add Prometheus metrics: feature_extraction_latency_ms, redis_operation_latency_ms
```

### Deliverable
- Every flow passing through the pipeline gets enriched with 45 features
- Redis stores rolling aggregates per IP
- Feature extraction runs in < 10ms
- Memory-only mode works without Redis (for dev/demo)

### Verification
```bash
# Start pipeline
docker compose up -d
netguard run --config configs/default.yaml &

# Generate traffic for 2 minutes
netguard generate --profile normal --rate 500 --duration 120 --output kafka://localhost:9092/raw-flows

# Check Redis has profiles
redis-cli HGETALL ip_profile:10.0.1.23
# Should show: unique_dst_ips_1m, bytes_out_1m, connection_count_1m, etc.
```

---

## Phase 3: Machine Learning Models (Week 5-6)

### Goal
Implement all three model types, the ensemble scorer, and the adaptive threshold. Train batch models on CICIDS2017.

### Tasks

```
[ ] 3.1 Online Model (Half-Space Trees)
    [ ] Implement online_model.py using River library
    [ ] Configure: n_trees=30, height=8, window_size=1000
    [ ] Add StandardScaler in pipeline (auto-normalizes)
    [ ] Verify: score_one() returns 0-1, learn_one() updates state
    [ ] Benchmark: < 1ms per score + learn cycle
    [ ] Add model state serialization (save/load for restart)

[ ] 3.2 Autoencoder Model
    [ ] Implement TrafficAutoencoder (PyTorch)
    [ ] Architecture: 45 → 32 → 16 → 8 → 16 → 32 → 45
    [ ] Training script (train_autoencoder.py):
        - Load CICIDS2017 benign flows
        - Normalize features to [0, 1]
        - Train 50 epochs, Adam optimizer, MSE loss
        - Early stopping on validation loss
        - Save best model checkpoint
    [ ] Inference wrapper: features → reconstruction error → normalized score
    [ ] Ship pre-trained model with package (trained on CICIDS2017)
    [ ] Benchmark: < 5ms inference (CPU), < 1ms (GPU)

[ ] 3.3 XGBoost Classifier
    [ ] Implement classifier.py
    [ ] Training script (train_classifier.py):
        - Load CICIDS2017 (all labels)
        - Stratified train/val/test split (70/15/15)
        - Train XGBClassifier with early stopping
        - Evaluate: confusion matrix, per-class F1, macro F1
        - Save model (JSON format for portability)
    [ ] Inference: features → probability distribution over 7 classes
    [ ] Ship pre-trained model with package
    [ ] Add SHAP explainability (feature importance per prediction)

[ ] 3.4 Ensemble Scorer
    [ ] Implement ensemble.py:
        - Collect scores from all active models
        - Apply configurable weights
        - Compute weighted final score
        - If anomalous: get attack classification from XGBoost
    [ ] Handle model failures gracefully (if one model errors, use remaining)
    [ ] Add model health monitoring (score distribution, latency)
    [ ] Make weights configurable via YAML and runtime API

[ ] 3.5 Adaptive Threshold
    [ ] Implement threshold.py:
        - Rolling percentile (99.5th of last 10K scores)
        - Time-of-day adjustment factors
        - Attack-mode tightening
    [ ] Implement fallback: if insufficient data, use fixed threshold (0.7)
    [ ] Add segment-based thresholds (different threshold per subnet/role)
    [ ] Threshold history tracking (for dashboard visualization)

[ ] 3.6 Model Evaluation & Notebooks
    [ ] Create 01_eda_cicids.ipynb — explore dataset, class distribution
    [ ] Create 02_feature_analysis.ipynb — feature correlations, importance
    [ ] Create 03_model_comparison.ipynb — compare all models, ROC curves
    [ ] Document expected performance metrics per attack type
    [ ] Verify ensemble beats individual models
```

### Deliverable
- All three models trained and producing scores
- Ensemble combines scores with configurable weights
- Adaptive threshold adjusts automatically
- Pre-trained models ship with the package
- Jupyter notebooks document model performance

### Verification
```bash
# Train models (one-time)
netguard train --data ./data/cicids2017/ --model autoencoder --output ./models/
netguard train --data ./data/cicids2017/ --model xgboost --output ./models/

# Run full pipeline with scoring
netguard run --config configs/default.yaml &
netguard generate --profile mixed --attack-ratio 0.05 --rate 500 --duration 60 --output kafka://localhost:9092/raw-flows

# Check scoring is working
curl http://localhost:8080/api/v1/models/status
# Should show all models loaded, scoring active
```

---

## Phase 4: Detection & Alerting (Week 7)

### Goal
Build the rules engine, threat intelligence matching, alert correlation/deduplication, and routing to outputs.

### Tasks

```
[ ] 4.1 Rules Engine
    [ ] Implement rules engine framework (evaluate rules per flow)
    [ ] Built-in rules:
        - port_scan (horizontal + vertical)
        - syn_flood
        - brute_force (SSH, RDP, FTP)
        - dns_tunnel
        - c2_beacon (periodicity check)
        - lateral_movement
        - data_exfiltration
    [ ] YAML rule loading (user-defined rules)
    [ ] Rule evaluation < 2ms per flow
    [ ] Unit tests per rule with known attack patterns

[ ] 4.2 Threat Intelligence
    [ ] Implement IOC (Indicator of Compromise) database
    [ ] Load sources:
        - IP blacklists (abuse.ch, emerging threats)
        - Domain blacklists
        - Known C2 server lists
    [ ] Redis-based lookup (O(1) per check)
    [ ] Auto-update mechanism (fetch new IOCs daily)
    [ ] IOC match → severity=critical (bypass ensemble)

[ ] 4.3 Alert Manager
    [ ] Alert generation: score + threshold + classification → Alert object
    [ ] Deduplication:
        - Same src+dst+type within 5 minutes = single alert
        - Increment occurrence counter instead
        - Escalate if occurrences > threshold
    [ ] Correlation:
        - Group alerts from same source IP
        - Detect multi-stage attacks (kill chain matching)
        - Create "incident" when correlated alerts detected
    [ ] Severity scoring:
        - critical: confirmed active attack (IOC match or high-confidence multi-signal)
        - high: high-confidence anomaly from ensemble
        - medium: single model flag or rule match
        - low: minor deviation, informational

[ ] 4.4 Alert Routing
    [ ] Route based on severity → output mapping
    [ ] Implement all built-in outputs:
        - ConsoleOutput (colored terminal)
        - WebhookOutput (POST to any URL)
        - SlackOutput (formatted Slack messages)
        - FileSink (JSON Lines)
        - KafkaSink (alert topic)
    [ ] Rate limiting: max N alerts per minute per output
    [ ] Retry logic for failed deliveries (exponential backoff)

[ ] 4.5 Attack Generators (Complete Suite)
    [ ] Implement all attack generators:
        - generate_port_scan()
        - generate_syn_flood()
        - generate_brute_force()
        - generate_c2_beacon()
        - generate_lateral_movement()
        - generate_dns_tunnel()
        - generate_exfiltration()
    [ ] Implement multi-step scenarios:
        - apt_kill_chain
        - botnet_recruitment
        - insider_threat
    [ ] CLI: netguard generate --attack <type> / --scenario <name>

[ ] 4.6 Integration Testing
    [ ] End-to-end test: inject port_scan → verify alert generated
    [ ] End-to-end test: inject syn_flood → verify critical alert
    [ ] End-to-end test: inject brute_force → verify alert with correct type
    [ ] End-to-end test: inject normal traffic → verify no false alerts
    [ ] End-to-end test: run APT scenario → verify correlated incident
    [ ] Measure: detection latency, false positive rate, detection rate
```

### Deliverable
- Rules engine catches known patterns instantly
- Threat intel blocks known-bad IPs/domains
- Alerts are deduplicated and correlated
- Multiple output channels working
- Complete attack generator suite for testing

### Verification
```bash
# Start full pipeline
netguard run --config configs/default.yaml &

# Inject attack and watch for alert
netguard generate --attack port_scan --target 10.0.1.50 --ports 100 --output kafka://localhost:9092/raw-flows

# Check alerts
curl http://localhost:8080/api/v1/alerts
# Should show: {severity: "high", attack_type: "port_scan", src_ip: "...", ...}

# Check Slack (if configured)
# Should see formatted alert message in channel
```

---

## Phase 5: API & Dashboard (Week 8)

### Goal
Build the REST API for external integrations and real-time Grafana dashboards for monitoring.

### Tasks

```
[ ] 5.1 FastAPI Application
    [ ] Implement API server (src/netguard/api/app.py)
    [ ] Endpoints:
        - POST /api/v1/score — score a single flow (real-time)
        - GET /api/v1/alerts — list recent alerts (with filtering)
        - GET /api/v1/alerts/{id} — alert detail
        - GET /api/v1/alerts/stream — SSE stream of live alerts
        - POST /api/v1/feedback — analyst labels an alert (true/false positive)
        - GET /api/v1/models/status — model health and versions
        - GET /api/v1/stats — system metrics (throughput, latency, alert rate)
        - PUT /api/v1/config — update runtime config (weights, thresholds)
        - GET /api/v1/health — health check endpoint
    [ ] Pydantic request/response schemas
    [ ] Authentication (API key or JWT — configurable)
    [ ] Rate limiting
    [ ] OpenAPI docs auto-generated at /docs

[ ] 5.2 Prometheus Metrics
    [ ] Expose metrics endpoint (/metrics)
    [ ] Key metrics:
        - netguard_flows_processed_total (counter)
        - netguard_flows_per_second (gauge)
        - netguard_scoring_latency_ms (histogram)
        - netguard_alerts_total (counter, by severity and type)
        - netguard_alerts_per_minute (gauge)
        - netguard_model_score_distribution (histogram, by model)
        - netguard_threshold_current (gauge)
        - netguard_kafka_consumer_lag (gauge)
        - netguard_redis_latency_ms (histogram)
        - netguard_feature_extraction_latency_ms (histogram)
    [ ] Add metrics to all pipeline stages

[ ] 5.3 Grafana Dashboards
    [ ] Traffic Overview Dashboard:
        - Flows per second (time series)
        - Bytes per second (in/out)
        - Protocol distribution (pie chart)
        - Top source IPs (table)
        - Top destination ports (bar chart)
    [ ] Alert Feed Dashboard:
        - Alert timeline (annotations on graph)
        - Alert count by severity (bar chart)
        - Alert count by attack type (pie chart)
        - Recent alerts table (with links to detail)
        - Alert rate (alerts/minute over time)
    [ ] Model Performance Dashboard:
        - Score distribution per model (histogram)
        - Current threshold value (single stat)
        - False positive rate (over time)
        - Model inference latency (per model)
        - Ensemble weight visualization
    [ ] System Health Dashboard:
        - Kafka consumer lag
        - Redis memory usage
        - CPU/memory per component
        - End-to-end latency (p50, p95, p99)
        - Error rates

[ ] 5.4 Feedback Loop
    [ ] POST /api/v1/feedback stores analyst label in PostgreSQL
    [ ] Accumulate feedback for next model retrain cycle
    [ ] Dashboard shows: alerts awaiting review, confirmed/dismissed ratio
    [ ] Use feedback to adjust ensemble weights over time
```

### Deliverable
- REST API with full OpenAPI documentation
- Real-time alert streaming (SSE)
- 4 Grafana dashboards pre-configured
- Analyst feedback loop functional
- Prometheus metrics covering all pipeline stages

### Verification
```bash
# Start everything
docker compose up -d
netguard run --config configs/default.yaml &
netguard generate --profile mixed --attack-ratio 0.03 --rate 500 --output kafka://localhost:9092/raw-flows &

# Access dashboards
open http://localhost:3000  # Grafana
open http://localhost:8080/docs  # API docs

# Test API
curl http://localhost:8080/api/v1/stats
curl http://localhost:8080/api/v1/alerts?severity=high
curl -X POST http://localhost:8080/api/v1/feedback -d '{"alert_id": "...", "label": "true_positive"}'
```

---

## Phase 6: Polish, Testing & Release (Week 9-10)

### Goal
Production-hardening, comprehensive testing, documentation, and open-source release.

### Tasks

```
[ ] 6.1 CLI Completion
    [ ] Implement all CLI commands:
        - netguard run — start detection pipeline
        - netguard demo — run with in-memory everything + synthetic data
        - netguard generate — generate traffic
        - netguard replay — replay dataset
        - netguard train — train batch models
        - netguard evaluate — model evaluation
        - netguard serve — API server only
        - netguard validate — validate config file
    [ ] Add --help with examples for each command
    [ ] Add --verbose/--quiet flags
    [ ] Add colored output (rich library)

[ ] 6.2 Demo Mode (Zero Dependencies)
    [ ] netguard demo starts everything in-process:
        - In-memory Kafka replacement (asyncio queues)
        - In-memory feature store (dict-based)
        - Pre-trained models (bundled with package)
        - Synthetic traffic generator
        - Console output (colored alerts)
        - Optionally start web UI on localhost:8080
    [ ] Should work on any machine with just: pip install netguard && netguard demo
    [ ] Prints "attack detected" within seconds of starting

[ ] 6.3 Load Testing
    [ ] Script: scripts/load_test.py
    [ ] Test at 1K, 5K, 10K, 20K flows/sec
    [ ] Measure: throughput, latency (p50/p95/p99), memory usage
    [ ] Identify bottlenecks and optimize
    [ ] Document results in benchmarks section
    [ ] Target: 10K flows/sec with < 100ms p95 latency on Tier 2 hardware

[ ] 6.4 Testing Suite
    [ ] Unit tests (target: >80% coverage):
        - Feature extraction (known inputs → expected outputs)
        - Each model's scoring (boundary cases)
        - Rules engine (attack patterns → correct triggers)
        - Threshold calculation
        - Alert deduplication logic
    [ ] Integration tests:
        - Full pipeline with embedded Kafka (testcontainers)
        - Inject attack → verify alert in output
        - Config loading and validation
    [ ] Performance tests:
        - Score 10K flows → measure time
        - Redis operations under load
        - Memory leak detection (long-running test)

[ ] 6.5 Documentation
    [ ] docs/quickstart.md — 5-minute getting started
    [ ] docs/configuration.md — complete config reference
    [ ] docs/custom-models.md — writing your own model
    [ ] docs/custom-adapters.md — writing your own adapter
    [ ] docs/deployment.md — production deployment guide
    [ ] docs/api-reference.md — REST API documentation
    [ ] docs/contributing.md — how to contribute
    [ ] Update README.md with badges, screenshots, quick start

[ ] 6.6 PyPI & Docker Publishing
    [ ] Configure pyproject.toml for PyPI publishing
    [ ] Build wheel: uv build
    [ ] Publish to PyPI: uv publish (or test PyPI first)
    [ ] Build Docker image: Dockerfile (multi-stage, slim)
    [ ] Publish to GitHub Container Registry (ghcr.io)
    [ ] Create GitHub Actions workflow:
        - CI: lint + type check + tests on every PR
        - Release: build + publish to PyPI + Docker on tag

[ ] 6.7 Open Source Release
    [ ] Final code review pass
    [ ] Remove any hardcoded values, secrets, internal references
    [ ] Add CHANGELOG.md
    [ ] Add CONTRIBUTING.md
    [ ] Add CODE_OF_CONDUCT.md
    [ ] Create GitHub repo with proper description and topics
    [ ] Add GitHub issue templates (bug report, feature request)
    [ ] Create initial release (v0.1.0) with release notes
    [ ] Record demo video (2-3 minutes) showing:
        - Install
        - Start demo mode
        - See attacks detected
        - Show Grafana dashboard
```

### Deliverable
- Installable via `pip install netguard`
- `netguard demo` works with zero external dependencies
- Handles 10K+ flows/sec on modest hardware
- Comprehensive test suite passing
- Full documentation
- Published on PyPI and Docker Hub
- GitHub repo with CI/CD

### Verification
```bash
# Test pip install (from TestPyPI first)
pip install netguard
netguard --version
netguard demo  # should start detecting attacks within 10 seconds

# Docker deployment
docker compose up  # full production stack

# Load test
netguard generate --profile mixed --rate 10000 --duration 60 --output kafka://localhost:9092/raw-flows
# Monitor Grafana: should handle 10K/s without lag buildup
```

---

## Post-Release Roadmap (Future)

```
[ ] v0.2.0 — Enhanced Detection
    [ ] Deep packet inspection (payload analysis)
    [ ] JA3/JA3S fingerprinting (TLS client identification)
    [ ] Encrypted traffic analysis (without decryption)
    [ ] GeoIP enrichment (impossible travel detection)
    [ ] User-Entity Behavior Analytics (UEBA) profiles

[ ] v0.3.0 — Scale & Enterprise
    [ ] Kubernetes Helm chart
    [ ] Multi-tenant support
    [ ] RBAC for API
    [ ] Horizontal auto-scaling (K8s HPA integration)
    [ ] Multi-site federation (aggregate alerts from multiple NetGuard instances)

[ ] v0.4.0 — Advanced ML
    [ ] Graph Neural Network (model network topology + behavior)
    [ ] Reinforcement learning for threshold tuning
    [ ] Federated learning (learn from multiple deployments without sharing data)
    [ ] LLM-powered alert summarization and investigation assistance

[ ] v1.0.0 — Production GA
    [ ] 99.99% uptime guarantee
    [ ] Enterprise support tier
    [ ] Compliance certifications (SOC2 evidence generation)
    [ ] Full MITRE ATT&CK mapping for detections
```

---

## Dependencies Between Phases

```
Phase 1 (Foundation)
    │
    ├──▶ Phase 2 (Features) ──────┐
    │                              │
    └──▶ Phase 3 (Models) ────────┼──▶ Phase 4 (Detection) ──▶ Phase 5 (API) ──▶ Phase 6 (Release)
                                   │
                                   │
    Note: Phase 2 and 3 can partially overlap.
    Phase 2's output (features) is needed before Phase 3's models can score real data.
    But model training (Phase 3.2, 3.3) can happen in parallel on CICIDS2017 dataset.
```

---

## Key Risk & Mitigation

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Kafka complexity for new users | High (friction) | Demo mode with zero dependencies |
| Model overfitting to CICIDS2017 | Medium | Online model adapts; clear docs about retraining |
| Redis as single point of failure | Medium | Memory-only fallback mode |
| False positive fatigue | High | Adaptive threshold + analyst feedback loop |
| Performance bottleneck at scale | Medium | Horizontal scaling design from day 1 |
| Concept drift (network changes) | Medium | Online model auto-adapts; batch models retrain nightly |
