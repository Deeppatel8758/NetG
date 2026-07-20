# Deployment Guide

## Deployment Options

| Method | Best For | Setup Time | External Deps |
|--------|---------|------------|---------------|
| `netguard demo` | Quick evaluation, learning | 1 minute | None |
| `pip install` + config | Embedded in existing Python project | 5 minutes | Redis (optional) |
| Docker Compose | Single-server production | 10 minutes | Docker |
| Kubernetes (Helm) | Enterprise, multi-node | 30 minutes | K8s cluster |

---

## Option 1: Demo Mode (Zero Dependencies)

```bash
pip install netguard
netguard demo
```

This runs everything in-process:
- Synthetic traffic generator (no Kafka needed)
- In-memory feature store (no Redis needed)
- Pre-trained models (bundled)
- Console output (colored alerts)
- Optional web UI at http://localhost:8080

---

## Option 2: Library Mode (Embedded)

```bash
pip install netguard
```

```python
from netguard import NetGuard

detector = NetGuard.from_config("netguard.yaml")
detector.start()
```

Minimal `netguard.yaml`:
```yaml
netguard:
  source:
    type: kafka
    kafka:
      brokers: ["localhost:9092"]
      topic: "network-flows"
  features:
    store:
      type: memory  # no Redis needed
  outputs:
    - type: console
    - type: webhook
      url: "http://my-app:5000/alerts"
```

---

## Option 3: Docker Compose (Recommended for Production)

### Prerequisites
- Docker Engine 24+
- Docker Compose v2
- 16 GB RAM available
- 50 GB disk space

### Setup

```bash
# Clone repository
git clone https://github.com/yourusername/netguard.git
cd netguard

# Copy and edit configuration
cp configs/default.yaml netguard.yaml
# Edit netguard.yaml with your settings

# Set environment variables
cp .env.example .env
# Edit .env: SLACK_WEBHOOK_URL, etc.

# Start all services
docker compose up -d

# Verify everything is running
docker compose ps
docker compose logs netguard --tail 20
```

### docker-compose.yml (Production)

```yaml
services:
  # === Message Broker ===
  kafka:
    image: bitnami/kafka:3.7
    ports:
      - "9092:9092"
    environment:
      - KAFKA_CFG_NODE_ID=0
      - KAFKA_CFG_PROCESS_ROLES=controller,broker
      - KAFKA_CFG_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093
      - KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      - KAFKA_CFG_CONTROLLER_QUORUM_VOTERS=0@kafka:9093
      - KAFKA_CFG_CONTROLLER_LISTENER_NAMES=CONTROLLER
      - KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE=true
      - KAFKA_CFG_LOG_RETENTION_HOURS=24
    volumes:
      - kafka_data:/bitnami/kafka
    healthcheck:
      test: kafka-topics.sh --bootstrap-server localhost:9092 --list
      interval: 10s
      timeout: 5s
      retries: 5

  # === Feature Store ===
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: redis-cli ping
      interval: 5s
      timeout: 3s
      retries: 5

  # === Storage ===
  postgres:
    image: timescale/timescaledb:latest-pg16
    ports:
      - "5432:5432"
    environment:
      POSTGRES_DB: netguard
      POSTGRES_USER: netguard
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-netguard_dev}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init_db.sql:/docker-entrypoint-initdb.d/01-init.sql
    healthcheck:
      test: pg_isready -U netguard
      interval: 5s
      timeout: 3s
      retries: 5

  # === Core Application ===
  netguard:
    image: ghcr.io/yourusername/netguard:latest
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - NETGUARD_CONFIG=/app/config.yaml
      - REDIS_URL=redis://redis:6379
      - KAFKA_BROKERS=kafka:9092
      - DATABASE_URL=postgresql://netguard:${POSTGRES_PASSWORD:-netguard_dev}@postgres:5432/netguard
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-}
    volumes:
      - ./netguard.yaml:/app/config.yaml:ro
      - ./models:/app/models:ro
    depends_on:
      kafka:
        condition: service_healthy
      redis:
        condition: service_healthy
      postgres:
        condition: service_healthy
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "4"
          memory: 4G

  # === Monitoring ===
  prometheus:
    image: prom/prometheus:v2.50.0
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.retention.time=15d'

  grafana:
    image: grafana/grafana:10.3.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}
      - GF_INSTALL_PLUGINS=grafana-clock-panel
    volumes:
      - ./dashboards/provisioning:/etc/grafana/provisioning:ro
      - ./dashboards/json:/var/lib/grafana/dashboards:ro
      - grafana_data:/var/lib/grafana

  # === Traffic Generator (for demo/testing only) ===
  traffic-gen:
    image: ghcr.io/yourusername/netguard:latest
    command: netguard generate --profile mixed --attack-ratio 0.03 --rate 500 --output kafka://kafka:9092/raw-flows
    depends_on:
      kafka:
        condition: service_healthy
    profiles:
      - demo  # only starts with: docker compose --profile demo up

volumes:
  kafka_data:
  redis_data:
  postgres_data:
  prometheus_data:
  grafana_data:
```

### Starting with Demo Traffic

```bash
# Start infrastructure + demo traffic generator
docker compose --profile demo up -d

# Access:
# - Grafana dashboard: http://localhost:3000 (admin/admin)
# - API docs: http://localhost:8080/docs
# - Prometheus: http://localhost:9090
```

### Connecting Your Real Network Data

```bash
# Option A: Send flows to Kafka topic from your collector
# Configure your NetFlow/sFlow/Zeek to send to kafka:9092, topic "raw-flows"

# Option B: Point at pcap file
docker compose exec netguard netguard replay --input /data/capture.pcap --output kafka://kafka:9092/raw-flows

# Option C: Direct socket capture (requires host networking)
# Add to docker-compose.yml for netguard service:
#   network_mode: host
#   cap_add:
#     - NET_RAW
# Then set source type to "socket" with your interface name
```

---

## Option 4: Kubernetes Deployment

### Helm Chart (Future — v0.3.0)

```bash
helm repo add netguard https://yourusername.github.io/netguard-helm
helm install netguard netguard/netguard \
  --set kafka.brokers="kafka-headless:9092" \
  --set redis.url="redis://redis-master:6379" \
  --set config.source.topic="network-flows" \
  --set outputs.slack.webhookUrl="$SLACK_WEBHOOK_URL"
```

---

## Monitoring & Alerting

### System Health Alerts (Alertmanager)

Configure alerts for operational issues (separate from security alerts):

```yaml
# monitoring/alerts.yml
groups:
  - name: netguard_system
    rules:
      - alert: HighKafkaLag
        expr: netguard_kafka_consumer_lag > 10000
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Kafka consumer lag is high ({{ $value }})"

      - alert: HighScoringLatency
        expr: histogram_quantile(0.95, netguard_scoring_latency_ms_bucket) > 100
        for: 5m
        labels:
          severity: warning

      - alert: ModelUnhealthy
        expr: netguard_model_healthy == 0
        for: 1m
        labels:
          severity: critical

      - alert: HighFalsePositiveRate
        expr: netguard_false_positive_rate_1h > 0.05
        for: 30m
        labels:
          severity: warning
```

---

## Backup & Recovery

### What to Back Up

| Component | What | How | Frequency |
|-----------|------|-----|-----------|
| PostgreSQL | Alerts, feedback, config | pg_dump | Daily |
| Model artifacts | Trained models | Copy to S3/backup dir | After each training |
| Configuration | netguard.yaml, rules | Git (version control) | Every change |
| Grafana | Dashboard JSON | Provisioning files (in Git) | Every change |
| Redis | Feature store | Not needed (reconstructs from stream) | - |

### Recovery

```bash
# Restore PostgreSQL
pg_restore -d netguard backup.dump

# Models auto-reload from ./models/ directory on restart
docker compose restart netguard

# Redis rebuilds feature store from live traffic within ~5 minutes
# (rolling windows re-populate as flows arrive)
```

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| API access | API key authentication (configurable) |
| Kafka access | SASL/SSL in production (configure in YAML) |
| Redis access | Password + bind to internal network only |
| PostgreSQL access | Strong password + SSL + limited network access |
| Secrets in config | Environment variable interpolation (`${VAR}`) |
| Container privileges | Run as non-root, drop capabilities |
| Network capture | Requires NET_RAW capability (only if using socket adapter) |
