# Plugin System & Extensibility

## Overview

NetGuard is designed as a framework, not a monolithic application. Every major component is pluggable through abstract base classes and a registry pattern.

```
┌─────────────────────────────────────────────────────────────────┐
│                    User's Project                                 │
│                                                                  │
│   from netguard import NetGuard                                  │
│   from netguard.adapters import KafkaAdapter                     │
│   from netguard.outputs import SlackOutput                       │
│                                                                  │
│   # Or bring your own:                                           │
│   from my_company.adapters import ProprietaryFirewallAdapter     │
│   from my_company.models import CustomTransformerModel           │
│                                                                  │
│   detector = NetGuard(                                           │
│       source=ProprietaryFirewallAdapter(config),                 │
│       outputs=[SlackOutput(webhook_url="...")],                   │
│   )                                                              │
│   detector.add_model(CustomTransformerModel(), weight=0.4)       │
│   detector.start()                                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Extension Points

| Extension Point | Base Class | Method to Implement | Purpose |
|----------------|-----------|--------------------|---------| 
| Input Source | `SourceAdapter` | `async stream()` | Read from any data source |
| Feature Extractor | `FeatureExtractor` | `extract(flow)` | Custom feature computation |
| ML Model | `AnomalyModel` | `score(features)` | Custom anomaly scoring |
| Threshold Strategy | `ThresholdStrategy` | `get_current()` | Custom threshold logic |
| Output Sink | `OutputSink` | `async emit(alert)` | Send alerts anywhere |
| Rule | `Rule` | `evaluate(flow, context)` | Custom detection rules |

---

## Input Adapters

### Base Class

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import AsyncIterator

@dataclass
class NetworkFlow:
    """Standard flow schema — all adapters must produce this."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str          # "TCP", "UDP", "ICMP"
    duration: float
    bytes_fwd: int
    bytes_bwd: int
    packets_fwd: int
    packets_bwd: int
    tcp_flags: dict        # {"SYN": int, "ACK": int, ...}
    payload_entropy: float # 0.0 - 8.0

class SourceAdapter(ABC):
    """Base class for all input adapters."""

    @abstractmethod
    async def stream(self) -> AsyncIterator[NetworkFlow]:
        """Yield NetworkFlow objects from the data source."""
        ...

    async def start(self):
        """Optional: called once before streaming begins."""
        pass

    async def stop(self):
        """Optional: called when shutting down."""
        pass

    def health_check(self) -> bool:
        """Optional: return False if source is unhealthy."""
        return True
```

### Built-in Adapters

| Adapter | Source | Config |
|---------|--------|--------|
| `KafkaAdapter` | Kafka topic | brokers, topic, group_id |
| `PcapAdapter` | .pcap files | file_path, bpf_filter |
| `CsvAdapter` | CSV files | path, column_mapping, replay_speed |
| `ZeekAdapter` | Zeek JSON logs | log_dir, file_pattern |
| `SyslogAdapter` | Syslog UDP/TCP | bind_address, port, parser |
| `SocketAdapter` | Raw socket capture | interface, bpf_filter |
| `NetflowAdapter` | NetFlow v9/IPFIX | bind_port |

### Writing a Custom Adapter

```python
from netguard.adapters.base import SourceAdapter, NetworkFlow

class MyFirewallAdapter(SourceAdapter):
    """Read from our company's proprietary firewall log format."""

    def __init__(self, log_path: str, tail: bool = True):
        self.log_path = log_path
        self.tail = tail

    async def stream(self) -> AsyncIterator[NetworkFlow]:
        async for line in self._read_lines():
            parsed = self._parse_line(line)
            if parsed:
                yield NetworkFlow(
                    timestamp=parsed["ts"],
                    src_ip=parsed["src_addr"],
                    dst_ip=parsed["dst_addr"],
                    src_port=parsed["src_port"],
                    dst_port=parsed["dst_port"],
                    protocol=parsed["proto"].upper(),
                    duration=parsed["elapsed"],
                    bytes_fwd=parsed["bytes_sent"],
                    bytes_bwd=parsed["bytes_recv"],
                    packets_fwd=parsed["pkts_sent"],
                    packets_bwd=parsed["pkts_recv"],
                    tcp_flags=self._parse_flags(parsed.get("flags", "")),
                    payload_entropy=0.0,  # not available from this source
                )

    def _parse_line(self, line: str) -> dict | None:
        # Your proprietary format parsing logic here
        ...

    async def _read_lines(self):
        # Tail the file or read once
        ...
```

---

## ML Models

### Base Class

```python
from abc import ABC, abstractmethod

class AnomalyModel(ABC):
    """Base class for all anomaly detection models."""

    @abstractmethod
    def score(self, features: dict) -> float:
        """
        Score a single observation.
        
        Args:
            features: Dict of feature_name → value
            
        Returns:
            Anomaly score between 0.0 (normal) and 1.0 (anomalous)
        """
        ...

    def update(self, features: dict, label: float | None = None):
        """
        Optional: update model with new observation (online learning).
        
        Args:
            features: The observation
            label: Optional ground truth (0=normal, 1=anomaly)
        """
        pass

    def load(self, path: str):
        """Optional: load model weights from disk."""
        pass

    def save(self, path: str):
        """Optional: save model weights to disk."""
        pass

    @property
    def name(self) -> str:
        """Model name for logging/metrics."""
        return self.__class__.__name__

    @property
    def is_online(self) -> bool:
        """True if model supports incremental learning."""
        return False

    def health_check(self) -> dict:
        """Return model health status."""
        return {"status": "ok", "name": self.name}
```

### Writing a Custom Model

```python
from netguard.models.base import AnomalyModel
import torch

class MyAttentionModel(AnomalyModel):
    """Custom transformer-based anomaly detector."""

    def __init__(self, checkpoint: str, threshold: float = 0.7):
        self.model = self._load_checkpoint(checkpoint)
        self.threshold = threshold
        self.feature_names = [...]  # expected feature order

    def score(self, features: dict) -> float:
        tensor = torch.tensor(
            [features.get(f, 0.0) for f in self.feature_names],
            dtype=torch.float32
        ).unsqueeze(0)

        with torch.no_grad():
            output = self.model(tensor)
            # Your scoring logic
            anomaly_score = output.squeeze().item()

        return min(max(anomaly_score, 0.0), 1.0)

    @property
    def name(self) -> str:
        return "attention-anomaly-v1"

# Register with NetGuard
detector = NetGuard.from_config("config.yaml")
detector.add_model(MyAttentionModel("./model.pt"), weight=0.4)
```

---

## Output Sinks

### Base Class

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass

@dataclass
class Alert:
    id: str
    timestamp: float
    severity: str        # critical, high, medium, low, info
    attack_type: str
    confidence: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    description: str
    evidence: dict
    recommended_action: str

class OutputSink(ABC):
    """Base class for alert output destinations."""

    def __init__(self, min_severity: str = "low"):
        self.min_severity = min_severity
        self._severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @abstractmethod
    async def emit(self, alert: Alert):
        """Send the alert to this output."""
        ...

    def should_emit(self, alert: Alert) -> bool:
        """Filter based on minimum severity."""
        return self._severity_order.get(alert.severity, 0) >= self._severity_order.get(self.min_severity, 0)

    async def start(self):
        """Optional: called once at startup."""
        pass

    async def stop(self):
        """Optional: called at shutdown (flush buffers, close connections)."""
        pass
```

### Built-in Outputs

| Output | Destination | Config |
|--------|-------------|--------|
| `ConsoleOutput` | stdout (colored) | min_severity, format |
| `WebhookOutput` | Any HTTP endpoint | url, headers, min_severity |
| `SlackOutput` | Slack channel | webhook_url, channel, min_severity |
| `KafkaSink` | Kafka topic | brokers, topic |
| `FileSink` | JSON Lines file | path, rotation |
| `CallbackOutput` | Python function | callable |

### Writing a Custom Output

```python
from netguard.outputs.base import OutputSink, Alert
import httpx

class PagerDutyOutput(OutputSink):
    """Send critical alerts to PagerDuty."""

    def __init__(self, routing_key: str):
        super().__init__(min_severity="critical")
        self.routing_key = routing_key
        self.client = None

    async def start(self):
        self.client = httpx.AsyncClient()

    async def emit(self, alert: Alert):
        await self.client.post(
            "https://events.pagerduty.com/v2/enqueue",
            json={
                "routing_key": self.routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": f"[{alert.severity.upper()}] {alert.attack_type}: {alert.description}",
                    "source": f"netguard:{alert.src_ip}",
                    "severity": "critical",
                    "custom_details": alert.evidence,
                }
            }
        )

    async def stop(self):
        if self.client:
            await self.client.aclose()
```

---

## Threshold Strategies

### Base Class

```python
from abc import ABC, abstractmethod

class ThresholdStrategy(ABC):
    """Base class for threshold computation."""

    @abstractmethod
    def get_current(self, segment: str = "default") -> float:
        """Return the current threshold value (0.0 - 1.0)."""
        ...

    @abstractmethod
    def update(self, score: float, segment: str = "default"):
        """Feed a new score to update threshold state."""
        ...
```

### Built-in Strategies

| Strategy | Description | Best For |
|----------|-------------|----------|
| `FixedThreshold` | Static value (e.g., 0.7) | Testing, baseline |
| `PercentileThreshold` | Rolling Nth percentile | General use |
| `AdaptiveThreshold` | Percentile + time-of-day + attack-mode | Production |
| `ZScoreThreshold` | Flag if > N standard deviations | Statistical approach |

---

## Rules Engine

### Base Class

```python
from abc import ABC, abstractmethod

class Rule(ABC):
    """Base class for signature-based detection rules."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @property
    @abstractmethod
    def severity(self) -> str:
        ...

    @property
    @abstractmethod
    def attack_type(self) -> str:
        ...

    @abstractmethod
    def evaluate(self, flow: dict, context: dict) -> float:
        """
        Evaluate this rule against a flow.
        
        Args:
            flow: Current flow features
            context: IP profile and windowed aggregates from Redis
            
        Returns:
            Score 0.0 (not matched) to 1.0 (fully matched)
        """
        ...
```

### YAML-Defined Rules

Users can also add rules via YAML without writing Python:

```yaml
# custom_rules.yaml
rules:
  - name: my_custom_vpn_rule
    severity: medium
    attack_type: policy_violation
    conditions:
      - field: dst_port
        operator: in
        value: [1194, 1723, 500, 4500]
      - field: src_ip
        operator: in_subnet
        value: "10.0.1.0/24"
      - field: connection_count_5m
        operator: gt
        value: 10
    description: "Workstation subnet attempting VPN connections (policy violation)"
```

---

## Configuration Schema (Complete)

```yaml
netguard:
  # Input source
  source:
    type: kafka | pcap | csv | zeek | syslog | socket | custom
    # ... type-specific config

  # Feature engineering
  features:
    window_sizes: [60, 300, 3600]
    store:
      type: redis | memory
      # ... store-specific config

  # Models (list — all are scored, ensemble combines)
  models:
    - type: half_space_trees | isolation_forest | autoencoder | xgboost | custom
      weight: 0.30
      enabled: true
      params: {}

  # Threshold
  threshold:
    strategy: fixed | percentile | adaptive | zscore
    # ... strategy-specific config

  # Rules
  rules:
    - type: port_scan | brute_force | ddos | c2_beacon | custom
      enabled: true
      params: {}

  # Outputs (list — alerts sent to all matching)
  outputs:
    - type: console | webhook | slack | kafka | file | custom
      min_severity: low
      # ... type-specific config

  # API server
  server:
    enabled: true
    host: "0.0.0.0"
    port: 8080

  # Logging
  logging:
    level: INFO
    format: json | text
```

---

## Registering Custom Plugins

### Method 1: Direct Python API

```python
from netguard import NetGuard

detector = NetGuard.from_config("config.yaml")
detector.source = MyCustomAdapter(config)
detector.add_model(MyModel(), weight=0.4)
detector.add_output(MyOutput())
detector.add_rule(MyRule())
detector.start()
```

### Method 2: Entry Points (pip installable plugins)

```toml
# In your plugin's pyproject.toml:
[project.entry-points."netguard.adapters"]
my_firewall = "my_plugin.adapters:FirewallAdapter"

[project.entry-points."netguard.models"]
my_transformer = "my_plugin.models:TransformerModel"

[project.entry-points."netguard.outputs"]
my_siem = "my_plugin.outputs:SIEMOutput"
```

Then in config:
```yaml
netguard:
  source:
    type: my_firewall  # auto-discovered via entry points
    config:
      log_path: /var/log/firewall/
```

### Method 3: Plugin directory

```
my_project/
├── netguard.yaml
├── plugins/
│   ├── my_adapter.py    # auto-loaded if contains SourceAdapter subclass
│   ├── my_model.py      # auto-loaded if contains AnomalyModel subclass
│   └── my_output.py     # auto-loaded if contains OutputSink subclass
└── ...
```
