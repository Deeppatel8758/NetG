# API Reference

## Base URL

```
http://localhost:8080/api/v1
```

## Authentication

All endpoints require an API key (when auth is enabled):

```
Authorization: Bearer <your-api-key>
```

Configure in `netguard.yaml`:
```yaml
netguard:
  server:
    auth:
      enabled: true
      api_keys: ["${NETGUARD_API_KEY}"]
```

---

## Endpoints

### POST /score

Score a single network flow in real-time.

**Request:**
```json
{
  "src_ip": "10.0.1.45",
  "dst_ip": "203.0.113.50",
  "src_port": 52341,
  "dst_port": 443,
  "protocol": "TCP",
  "duration": 1.23,
  "bytes_fwd": 1520,
  "bytes_bwd": 45230,
  "packets_fwd": 12,
  "packets_bwd": 35,
  "tcp_flags": {"SYN": 1, "ACK": 30, "FIN": 1, "RST": 0, "PSH": 8, "URG": 0},
  "payload_entropy": 6.82
}
```

**Response:**
```json
{
  "score": 0.23,
  "is_anomaly": false,
  "threshold": 0.72,
  "model_scores": {
    "online": 0.18,
    "autoencoder": 0.25,
    "xgboost": 0.31,
    "rules": 0.0
  },
  "attack_type": null,
  "confidence": null,
  "processing_time_ms": 12.5
}
```

**Anomaly detected:**
```json
{
  "score": 0.89,
  "is_anomaly": true,
  "threshold": 0.72,
  "model_scores": {
    "online": 0.92,
    "autoencoder": 0.85,
    "xgboost": 0.88,
    "rules": 0.95
  },
  "attack_type": "port_scan",
  "confidence": 0.91,
  "processing_time_ms": 15.2
}
```

---

### GET /alerts

List recent alerts with optional filtering.

**Query Parameters:**
| Param | Type | Default | Description |
|-------|------|---------|-------------|
| severity | string | all | Filter: critical, high, medium, low |
| attack_type | string | all | Filter: port_scan, ddos, brute_force, etc. |
| src_ip | string | - | Filter by source IP |
| since | ISO datetime | 1h ago | Start time |
| until | ISO datetime | now | End time |
| limit | int | 50 | Max results (1-500) |
| offset | int | 0 | Pagination offset |

**Example:**
```
GET /api/v1/alerts?severity=high&attack_type=port_scan&limit=10
```

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert_abc123",
      "timestamp": "2024-01-15T10:23:45Z",
      "severity": "high",
      "attack_type": "port_scan",
      "confidence": 0.91,
      "src_ip": "192.168.1.100",
      "dst_ip": "10.0.1.50",
      "src_port": null,
      "dst_port": null,
      "description": "Horizontal port scan detected: 10.0.1.100 scanned 87 ports on 10.0.1.50 in 60s",
      "evidence": {
        "unique_ports_scanned": 87,
        "window_seconds": 60,
        "model_scores": {"online": 0.92, "rules": 0.95},
        "triggered_rules": ["port_scan_horizontal"]
      },
      "recommended_action": "Investigate source host. Block if external. Check for compromise if internal.",
      "status": "open",
      "occurrences": 1
    }
  ],
  "total": 23,
  "limit": 10,
  "offset": 0
}
```

---

### GET /alerts/{id}

Get full detail for a single alert.

**Response:**
```json
{
  "id": "alert_abc123",
  "timestamp": "2024-01-15T10:23:45Z",
  "severity": "high",
  "attack_type": "port_scan",
  "confidence": 0.91,
  "src_ip": "192.168.1.100",
  "dst_ip": "10.0.1.50",
  "description": "...",
  "evidence": {
    "unique_ports_scanned": 87,
    "window_seconds": 60,
    "model_scores": {"online": 0.92, "autoencoder": 0.78, "xgboost": 0.85, "rules": 0.95},
    "triggered_rules": ["port_scan_horizontal"],
    "feature_snapshot": {
      "unique_dst_ports_1m": 87,
      "connection_count_1m": 93,
      "avg_duration_1m": 0.003,
      "bytes_per_packet_fwd": 44
    },
    "related_flows_sample": [
      {"src_port": 45231, "dst_port": 22, "timestamp": "..."},
      {"src_port": 45232, "dst_port": 80, "timestamp": "..."},
      {"src_port": 45233, "dst_port": 443, "timestamp": "..."}
    ]
  },
  "recommended_action": "...",
  "status": "open",
  "occurrences": 1,
  "first_seen": "2024-01-15T10:23:45Z",
  "last_seen": "2024-01-15T10:24:02Z",
  "related_alerts": ["alert_def456"],
  "feedback": null
}
```

---

### GET /alerts/stream

Server-Sent Events (SSE) stream of live alerts.

**Example:**
```bash
curl -N http://localhost:8080/api/v1/alerts/stream?min_severity=medium
```

**Response (SSE format):**
```
event: alert
data: {"id": "alert_abc123", "severity": "high", "attack_type": "port_scan", ...}

event: alert
data: {"id": "alert_def456", "severity": "critical", "attack_type": "ddos", ...}

event: heartbeat
data: {"timestamp": "2024-01-15T10:25:00Z", "alerts_last_minute": 3}
```

---

### POST /feedback

Submit analyst feedback on an alert (for model improvement).

**Request:**
```json
{
  "alert_id": "alert_abc123",
  "label": "true_positive",
  "notes": "Confirmed port scan from compromised workstation",
  "analyst": "john.doe"
}
```

**Label values:**
- `true_positive` — alert correctly identified a real threat
- `false_positive` — alert was incorrect (legitimate activity)
- `needs_investigation` — unclear, needs more info

**Response:**
```json
{
  "status": "accepted",
  "alert_id": "alert_abc123",
  "feedback_id": "fb_xyz789",
  "message": "Feedback recorded. 47 labeled samples pending next model retrain."
}
```

---

### GET /models/status

Get health and version info for all loaded models.

**Response:**
```json
{
  "models": [
    {
      "name": "half_space_trees",
      "type": "online",
      "status": "healthy",
      "weight": 0.30,
      "observations_processed": 1523400,
      "avg_score": 0.12,
      "p99_latency_ms": 0.8
    },
    {
      "name": "autoencoder_v3",
      "type": "batch",
      "status": "healthy",
      "weight": 0.30,
      "version": "v3.2.1",
      "trained_at": "2024-01-15T02:15:00Z",
      "training_samples": 850000,
      "val_loss": 0.0023,
      "avg_score": 0.15,
      "p99_latency_ms": 4.2
    },
    {
      "name": "xgboost_classifier_v5",
      "type": "batch",
      "status": "healthy",
      "weight": 0.25,
      "version": "v5.0.0",
      "trained_at": "2024-01-14T02:30:00Z",
      "macro_f1": 0.95,
      "classes": ["benign", "dos", "port_scan", "brute_force", "web_attack", "botnet", "infiltration"],
      "p99_latency_ms": 1.1
    }
  ],
  "ensemble": {
    "status": "healthy",
    "total_scored": 1523400,
    "alerts_generated": 234,
    "current_threshold": 0.72,
    "false_positive_rate_1h": 0.008
  }
}
```

---

### GET /stats

System-wide statistics and throughput metrics.

**Response:**
```json
{
  "throughput": {
    "flows_per_second": 4523,
    "flows_last_minute": 271380,
    "flows_last_hour": 16282800,
    "bytes_per_second": 2261500
  },
  "latency": {
    "end_to_end_p50_ms": 45,
    "end_to_end_p95_ms": 78,
    "end_to_end_p99_ms": 112,
    "scoring_p50_ms": 12,
    "scoring_p95_ms": 25
  },
  "alerts": {
    "total_today": 47,
    "by_severity": {"critical": 2, "high": 8, "medium": 23, "low": 14},
    "by_type": {"port_scan": 12, "brute_force": 8, "ddos": 2, "c2_beacon": 1, "other": 24},
    "alerts_per_minute_avg": 0.8
  },
  "infrastructure": {
    "kafka_consumer_lag": 124,
    "redis_memory_mb": 342,
    "redis_keys": 2847,
    "uptime_seconds": 86400
  }
}
```

---

### PUT /config

Update runtime configuration (no restart required).

**Request:**
```json
{
  "models": {
    "weights": {
      "online": 0.35,
      "autoencoder": 0.30,
      "xgboost": 0.20,
      "rules": 0.15
    }
  },
  "threshold": {
    "base_percentile": 99.0,
    "attack_mode": true
  }
}
```

**Response:**
```json
{
  "status": "updated",
  "changes": [
    "models.weights.online: 0.30 → 0.35",
    "models.weights.xgboost: 0.25 → 0.20",
    "threshold.base_percentile: 99.5 → 99.0",
    "threshold.attack_mode: false → true"
  ]
}
```

---

### GET /health

Health check endpoint (for load balancers / K8s probes).

**Response (healthy):**
```json
{
  "status": "healthy",
  "checks": {
    "kafka": "connected",
    "redis": "connected",
    "database": "connected",
    "models": "loaded"
  },
  "version": "0.1.0"
}
```

**Response (degraded):**
```json
{
  "status": "degraded",
  "checks": {
    "kafka": "connected",
    "redis": "timeout",
    "database": "connected",
    "models": "loaded"
  },
  "issues": ["Redis connection timeout — using in-memory fallback"]
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid flow data: 'src_ip' is required",
    "details": {...}
  }
}
```

| HTTP Code | Error Code | Description |
|-----------|-----------|-------------|
| 400 | VALIDATION_ERROR | Invalid request body |
| 401 | UNAUTHORIZED | Missing or invalid API key |
| 404 | NOT_FOUND | Resource not found |
| 429 | RATE_LIMITED | Too many requests |
| 500 | INTERNAL_ERROR | Server error |
| 503 | SERVICE_UNAVAILABLE | Dependency down |

---

## Rate Limits

| Endpoint | Default Limit | Configurable |
|----------|---------------|-------------|
| POST /score | 10,000/min | Yes |
| GET /alerts | 100/min | Yes |
| GET /alerts/stream | 10 concurrent | Yes |
| POST /feedback | 100/min | Yes |
| PUT /config | 10/min | Yes |

---

## WebSocket Alternative (Future)

```javascript
// Connect to WebSocket for bidirectional communication
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log(`Alert: ${alert.severity} - ${alert.attack_type}`);
};

// Send flow for scoring
ws.send(JSON.stringify({type: 'score', flow: {...}}));
```
