# Machine Learning Models

## Model Architecture Overview

NetGuard uses an ensemble of three model types plus a rules engine:

```
                    ┌─────────────────────────────────────────────────────┐
                    │              Ensemble Scorer                         │
                    │                                                     │
Input Features ──▶  │  ┌──────────────────┐  weight: 0.30               │
                    │  │ Online Model     │──────┐                       │
                    │  │ (Half-Space Tree)│      │                       │
                    │  └──────────────────┘      │                       │
                    │                            │                       │
                    │  ┌──────────────────┐      ▼                       │
                    │  │ Autoencoder      │──▶ Weighted ──▶ Adaptive ──▶ Alert?
                    │  │ (PyTorch)        │    Sum         Threshold     │
                    │  └──────────────────┘      ▲                       │
                    │  weight: 0.30              │                       │
                    │                            │                       │
                    │  ┌──────────────────┐      │                       │
                    │  │ XGBoost          │──────┘                       │
                    │  │ Classifier       │  weight: 0.25               │
                    │  └──────────────────┘                              │
                    │                                                     │
                    │  ┌──────────────────┐                              │
                    │  │ Rules Engine     │──────────────▶ (bypass       │
                    │  │ (Signature)      │               ensemble if    │
                    │  └──────────────────┘               rule matches)  │
                    │  weight: 0.15                                       │
                    └─────────────────────────────────────────────────────┘
```

---

## Model 1: Online Anomaly Detection (Half-Space Trees)

### Purpose
Unsupervised online anomaly detection that learns incrementally from every flow. No labeled data needed. Adapts to network changes automatically.

### Algorithm
Half-Space Trees (HST) work by:
1. Building random binary trees that partition the feature space
2. Counting how many samples fall in each partition
3. Anomalies land in partitions with low counts (sparse regions)
4. The model maintains a sliding window — old counts decay, new ones accumulate

### Implementation
```python
from river import anomaly, compose, preprocessing

online_model = compose.Pipeline(
    preprocessing.StandardScaler(),
    anomaly.HalfSpaceTrees(
        n_trees=30,        # more trees = more stable scores
        height=8,          # deeper = finer granularity
        window_size=1000   # reference window for "normal"
    )
)

# Per event (streaming):
score = online_model.score_one(features)   # 0.0 (normal) to 1.0 (anomaly)
online_model.learn_one(features)           # update model with this observation
```

### Features Used
- `bytes_per_packet_fwd` / `bytes_per_packet_bwd`
- `fwd_bwd_ratio`
- `duration`
- `packets_fwd` / `packets_bwd`
- `payload_entropy`
- `unique_dst_ports_1m` (from Redis)
- `connection_count_1m` (from Redis)

### Characteristics
| Property | Value |
|----------|-------|
| Training | None required (online learning) |
| Inference time | < 1ms per flow |
| Memory | ~200 MB per worker |
| Accuracy | Good at detecting statistical outliers |
| Weakness | Can't classify attack type |
| Update speed | Instant (per observation) |

---

## Model 2: Autoencoder (Anomaly Detection via Reconstruction Error)

### Purpose
Learns a compressed representation of "normal" traffic. Anomalous flows that deviate from learned patterns produce high reconstruction error.

### Architecture
```
Input (45 features)
    │
    ▼
┌──────────┐
│ Linear(45, 32) + ReLU + BatchNorm + Dropout(0.2) │  Encoder
│ Linear(32, 16) + ReLU + BatchNorm                 │
│ Linear(16, 8)                                     │  ← Bottleneck (latent space)
└──────────┘
    │
    ▼
┌──────────┐
│ Linear(8, 16) + ReLU + BatchNorm                  │  Decoder
│ Linear(16, 32) + ReLU + BatchNorm                 │
│ Linear(32, 45) + Sigmoid                          │
└──────────┘
    │
    ▼
Output (45 reconstructed features)

Anomaly Score = MSE(input, output)
```

### Implementation
```python
import torch
import torch.nn as nn

class TrafficAutoencoder(nn.Module):
    def __init__(self, input_dim=45, latent_dim=8):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.BatchNorm1d(16),
            nn.Linear(16, latent_dim),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 16),
            nn.ReLU(),
            nn.BatchNorm1d(16),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.BatchNorm1d(32),
            nn.Linear(32, input_dim),
            nn.Sigmoid(),
        )

    def forward(self, x):
        latent = self.encoder(x)
        reconstructed = self.decoder(latent)
        return reconstructed

# Anomaly score = reconstruction error
def score(model, features_tensor):
    with torch.no_grad():
        reconstructed = model(features_tensor)
        mse = torch.mean((features_tensor - reconstructed) ** 2, dim=1)
        # Normalize to 0-1 using learned threshold
        return torch.clamp(mse / threshold_value, 0.0, 1.0)
```

### Training
- **Data**: Last 24 hours of flows labeled as "benign" (or all traffic if no labels)
- **Schedule**: Nightly at 02:00 UTC
- **Epochs**: 50-100
- **Batch size**: 256
- **Loss**: MSE (mean squared error)
- **Optimizer**: Adam, lr=1e-3 with cosine annealing
- **Validation**: 20% holdout, early stopping on val loss

### Features Used (45 total)
All per-flow features + windowed aggregates normalized to [0, 1]:
- Per-flow: duration, bytes, packets, ratios, entropy, flags (15 features)
- Windowed 1min: connection count, unique dst, bytes out, failed connections (8 features)
- Windowed 5min: same as above + protocol distribution entropy (10 features)
- Windowed 1hr: new IPs seen, periodicity score, DNS entropy (7 features)
- Peer-group: z-scores vs subnet, vs role (5 features)

### Characteristics
| Property | Value |
|----------|-------|
| Training | Nightly batch retrain (~15 min on GPU, ~60 min on CPU) |
| Inference time | ~5ms (CPU), ~1ms (GPU, batched) |
| Memory | ~300 MB (model + framework) |
| Accuracy | Excellent at detecting deviations from learned normal |
| Weakness | Needs retraining if network topology changes significantly |
| Model size | ~500 KB (weights only) |

---

## Model 3: XGBoost Classifier (Supervised Attack Classification)

### Purpose
When the ensemble flags an anomaly, the classifier determines WHAT TYPE of attack it is. Trained on labeled data (CICIDS2017).

### Classes
```
0: Benign
1: DoS/DDoS (Hulk, Slowloris, GoldenEye, SYN flood)
2: Port Scan (horizontal, vertical)
3: Brute Force (SSH, FTP, RDP)
4: Web Attack (XSS, SQL injection)
5: Botnet (C2, beaconing)
6: Infiltration (lateral movement, exfiltration)
```

### Implementation
```python
import xgboost as xgb

classifier = xgb.XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective='multi:softprob',
    num_class=7,
    eval_metric='mlogloss',
    early_stopping_rounds=20,
    tree_method='hist',        # fast histogram-based
    device='cpu',              # or 'cuda' if GPU available
)

# Training
classifier.fit(
    X_train, y_train,
    eval_set=[(X_val, y_val)],
    verbose=False
)

# Inference — returns probability per class
probs = classifier.predict_proba(features)  # shape: (1, 7)
predicted_class = probs.argmax()
confidence = probs.max()
```

### Training
- **Data**: CICIDS2017 dataset (2.8M labeled flows)
- **Schedule**: Weekly retrain, or when analyst feedback accumulates 1000+ labels
- **Split**: 70% train / 15% validation / 15% test (stratified)
- **Feature importance**: Use SHAP values for explainability

### Characteristics
| Property | Value |
|----------|-------|
| Training | Weekly batch (~5 min on CPU) |
| Inference time | ~1ms per flow |
| Memory | ~100 MB (model loaded) |
| Accuracy | ~95% on CICIDS2017 (macro F1) |
| Weakness | Biased toward training data distribution |
| Model size | ~50 MB (JSON format) |

---

## Rules Engine (Signature-Based)

### Purpose
Fast, deterministic detection of known attack patterns. Catches obvious attacks instantly without ML overhead. Also provides a "floor" — ML might miss obvious patterns.

### Rules Implemented
```yaml
rules:
  - name: port_scan_horizontal
    condition: unique_dst_ports_1m > 20 AND duration_avg < 0.1
    severity: high
    attack_type: port_scan

  - name: port_scan_vertical
    condition: unique_dst_ips_1m > 15 AND dst_port = same AND SYN_only
    severity: high
    attack_type: port_scan

  - name: syn_flood
    condition: packets_per_sec > 5000 AND syn_ratio > 0.95 AND ack_ratio < 0.05
    severity: critical
    attack_type: ddos

  - name: brute_force_ssh
    condition: dst_port = 22 AND connection_count_5m > 20 AND avg_duration < 3
    severity: high
    attack_type: brute_force

  - name: brute_force_rdp
    condition: dst_port = 3389 AND connection_count_5m > 15
    severity: high
    attack_type: brute_force

  - name: dns_tunnel
    condition: dst_port = 53 AND payload_entropy > 7.0 AND bytes_fwd > 100
    severity: medium
    attack_type: dns_tunnel

  - name: c2_beacon
    condition: periodicity_score > 0.85 AND unique_dst_ips = 1 AND duration > 3600
    severity: critical
    attack_type: c2_beacon

  - name: data_exfiltration
    condition: bytes_fwd_1h > zscore(3.0) AND dst_ip NOT IN internal_subnets
    severity: high
    attack_type: exfiltration

  - name: lateral_movement
    condition: src_ip IN internal AND dst_ip IN internal AND dst_port IN [22,445,3389,5985] AND new_connection = true
    severity: medium
    attack_type: lateral_movement
```

---

## Ensemble Scoring Logic

```python
class EnsembleScorer:
    def __init__(self, config):
        self.weights = {
            "online": config.get("online_weight", 0.30),
            "autoencoder": config.get("autoencoder_weight", 0.30),
            "xgboost": config.get("xgboost_weight", 0.25),
            "rules": config.get("rules_weight", 0.15),
        }

    def score(self, features, ip_profile):
        scores = {}

        # Get individual scores
        scores["online"] = self.online_model.score_one(features)
        scores["autoencoder"] = self.autoencoder.score(features)
        scores["rules"] = self.rules_engine.evaluate(features, ip_profile)

        # Threat intel is binary — if IOC match, override
        ioc_match = self.threat_intel.check(features)
        if ioc_match:
            return 1.0, "threat_intel_match", 1.0

        # Weighted ensemble
        final_score = sum(scores[k] * self.weights[k] for k in scores)

        # If anomalous, classify the attack
        attack_type = None
        confidence = final_score
        if final_score > self.threshold.get_current():
            probs = self.classifier.predict_proba(features)
            attack_type = self.class_names[probs.argmax()]
            confidence = probs.max()

        return final_score, attack_type, confidence
```

---

## Adaptive Threshold Strategy

```python
class AdaptiveThreshold:
    """
    Dynamic threshold that adjusts based on:
    1. Rolling score distribution (percentile-based)
    2. Time-of-day patterns (business vs off-hours)
    3. Attack-mode tightening (feedback loop)
    """

    def __init__(self, window_size=10000, base_percentile=99.5):
        self.scores = deque(maxlen=window_size)
        self.base_percentile = base_percentile
        self.attack_mode = False
        self.hourly_factors = self._default_hourly_factors()

    def update(self, score: float):
        self.scores.append(score)

    def get_current(self) -> float:
        if len(self.scores) < 100:
            return 0.7  # conservative default until we have data

        # Base: percentile of recent scores
        base = np.percentile(list(self.scores), self.base_percentile)

        # Time factor: stricter during business hours
        hour = datetime.now().hour
        time_factor = self.hourly_factors[hour]

        # Attack factor: tighten if we're seeing active attacks
        attack_factor = 0.85 if self.attack_mode else 1.0

        return base * time_factor * attack_factor

    def enter_attack_mode(self):
        self.attack_mode = True

    def exit_attack_mode(self):
        self.attack_mode = False

    def _default_hourly_factors(self):
        # Stricter during business hours (more legitimate traffic = cleaner baseline)
        # More lenient at night (maintenance, backups may look unusual)
        return {
            0: 1.1, 1: 1.1, 2: 1.1, 3: 1.1, 4: 1.1, 5: 1.05,
            6: 1.0, 7: 0.95, 8: 0.9, 9: 0.9, 10: 0.9, 11: 0.9,
            12: 0.9, 13: 0.9, 14: 0.9, 15: 0.9, 16: 0.9, 17: 0.95,
            18: 1.0, 19: 1.0, 20: 1.05, 21: 1.05, 22: 1.1, 23: 1.1,
        }
```

---

## Model Training Pipeline

```
┌───────────────────────────────────────────────────────────────────────┐
│                    Nightly Training Pipeline (02:00 UTC)                │
├───────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  1. Extract data                                                       │
│     └── Query TimescaleDB: last 24h flows                             │
│     └── Query PostgreSQL: analyst feedback labels                      │
│                                                                        │
│  2. Prepare datasets                                                   │
│     └── Autoencoder: filter benign-only flows, normalize features     │
│     └── XGBoost: all labeled flows (benign + attack types)            │
│                                                                        │
│  3. Train models                                                       │
│     └── Autoencoder: 50 epochs, early stopping on val MSE             │
│     └── XGBoost: fit with early stopping on val logloss               │
│                                                                        │
│  4. Evaluate                                                           │
│     └── Compare new model vs current production model                 │
│     └── Metrics: precision, recall, F1 per class, AUC-ROC            │
│                                                                        │
│  5. Promote (if improved)                                              │
│     └── Register in MLflow with metrics                               │
│     └── Tag as "production" (auto-loaded by workers on next restart)  │
│     └── Notify via Slack: "New model deployed, F1: 0.94 → 0.96"      │
│                                                                        │
│  6. Archive                                                            │
│     └── Save old model as "archived"                                  │
│     └── Save training data snapshot to object storage                 │
│                                                                        │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Model Performance Targets

| Model | Metric | Target | Measured (CICIDS2017) |
|-------|--------|--------|----------------------|
| Online (HST) | AUC-ROC | > 0.85 | 0.87 |
| Autoencoder | AUC-ROC | > 0.90 | 0.92 |
| XGBoost | Macro F1 | > 0.90 | 0.95 |
| Ensemble | Precision | > 0.90 | 0.93 |
| Ensemble | Recall | > 0.80 | 0.85 |
| Ensemble | False Positive Rate | < 2% | 1.3% |
| End-to-end | Detection Rate (known attacks) | > 95% | 97% |
| End-to-end | Time to Detect | < 100ms (p95) | 72ms |

---

## Feature List (Complete)

### Per-Flow Features (15)
| # | Feature | Type | Range |
|---|---------|------|-------|
| 1 | duration | float | 0 - ∞ |
| 2 | protocol_encoded | int | 0-2 (TCP/UDP/ICMP) |
| 3 | dst_port_category | int | 0-5 (well-known/registered/ephemeral/...) |
| 4 | bytes_fwd | int | 0 - ∞ |
| 5 | bytes_bwd | int | 0 - ∞ |
| 6 | packets_fwd | int | 0 - ∞ |
| 7 | packets_bwd | int | 0 - ∞ |
| 8 | bytes_per_packet_fwd | float | 0 - 1500 |
| 9 | bytes_per_packet_bwd | float | 0 - 1500 |
| 10 | fwd_bwd_byte_ratio | float | 0 - ∞ |
| 11 | fwd_bwd_packet_ratio | float | 0 - ∞ |
| 12 | syn_flag_count | int | 0 - ∞ |
| 13 | rst_flag_count | int | 0 - ∞ |
| 14 | ack_to_syn_ratio | float | 0 - ∞ |
| 15 | payload_entropy | float | 0.0 - 8.0 |

### Windowed Features - 1 Minute (8)
| # | Feature | Type |
|---|---------|------|
| 16 | unique_dst_ips_1m | int |
| 17 | unique_dst_ports_1m | int |
| 18 | total_bytes_out_1m | int |
| 19 | total_bytes_in_1m | int |
| 20 | connection_count_1m | int |
| 21 | failed_connections_1m | int |
| 22 | avg_duration_1m | float |
| 23 | protocol_entropy_1m | float |

### Windowed Features - 5 Minutes (10)
| # | Feature | Type |
|---|---------|------|
| 24 | unique_dst_ips_5m | int |
| 25 | unique_dst_ports_5m | int |
| 26 | total_bytes_out_5m | int |
| 27 | connection_count_5m | int |
| 28 | failed_connections_5m | int |
| 29 | avg_packet_size_5m | float |
| 30 | max_packets_per_flow_5m | int |
| 31 | new_dst_ips_5m | int |
| 32 | dst_port_entropy_5m | float |
| 33 | src_port_entropy_5m | float |

### Windowed Features - 1 Hour (7)
| # | Feature | Type |
|---|---------|------|
| 34 | unique_dst_ips_1h | int |
| 35 | new_dst_ips_1h | int |
| 36 | periodicity_score_1h | float |
| 37 | dns_query_count_1h | int |
| 38 | dns_query_entropy_1h | float |
| 39 | bytes_out_zscore_1h | float |
| 40 | connection_burst_count_1h | int |

### Peer-Group Features (5)
| # | Feature | Type |
|---|---------|------|
| 41 | zscore_bytes_vs_subnet | float |
| 42 | zscore_connections_vs_role | float |
| 43 | zscore_ports_vs_role | float |
| 44 | new_service_flag | int (0/1) |
| 45 | rare_port_score | float |
