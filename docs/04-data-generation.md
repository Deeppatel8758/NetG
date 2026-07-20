# Test Data & Network Event Generation

## Overview

NetGuard includes a comprehensive traffic generation system for testing, demos, and development. It operates at multiple layers to produce realistic network data.

## Generation Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│                  Data Generation Layers                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Layer 1: Dataset Replay                                         │
│           └─ CICIDS2017, NSL-KDD — real labeled data             │
│           └─ Replay at configurable speed (1x - 1000x)           │
│                                                                  │
│  Layer 2: Statistical Generator                                  │
│           └─ Mimics distributions from real traffic              │
│           └─ Parameterized (rate, protocols, subnet topology)    │
│           └─ Time-of-day patterns, host roles                    │
│                                                                  │
│  Layer 3: Attack Scenario Engine                                 │
│           └─ Multi-step attack campaigns (APT kill chain)        │
│           └─ Configurable intensity, duration, type              │
│           └─ Realistic timing and evasion patterns               │
│                                                                  │
│  Layer 4: Live Capture Replay                                    │
│           └─ Replay .pcap files at original timestamps           │
│           └─ Rate-limited to simulate real-time                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Normal Traffic Generation

### Network Topology Simulation

```python
TrafficProfile:
    internal_subnets: ["10.0.1.0/24", "10.0.2.0/24", "192.168.1.0/24"]
    external_ips_pool: 500 unique simulated internet hosts
    
    Host Roles (assigned per internal IP):
    ├── Workstation (60%) — browses HTTP/HTTPS, DNS, some SSH
    ├── Server (20%) — serves HTTP/HTTPS/API, receives connections
    ├── Database (10%) — MySQL/PostgreSQL/Redis traffic, internal only
    ├── DNS Server (5%) — high DNS query volume
    └── Mail Server (5%) — SMTP/IMAP traffic
```

### Traffic Characteristics

| Parameter | Distribution | Realistic Values |
|-----------|-------------|-----------------|
| Flow duration | Exponential(λ=2.0) | Most < 5s, some long-lived |
| Bytes forward | LogNormal(μ=7, σ=1.5) | Median ~1KB, long tail |
| Bytes backward | LogNormal(μ=8, σ=2.0) | Responses typically larger |
| Packets per flow | Derived from bytes/MTU | 1-1000+ |
| Protocol mix | TCP:75%, UDP:20%, ICMP:5% | Typical enterprise |
| Dst port distribution | Weighted by service | 443 > 80 > 53 > 22 > ... |
| Payload entropy | Uniform(3.5, 7.0) | Varies by content type |

### Time-of-Day Pattern

```
Rate Multiplier by Hour:
Hour:  00   01   02   03   04   05   06   07   08   09   10   11
Rate:  0.2  0.1  0.1  0.1  0.15 0.3  0.5  0.8  1.0  1.0  0.95 0.9

Hour:  12   13   14   15   16   17   18   19   20   21   22   23
Rate:  0.85 0.9  1.0  1.0  0.95 0.8  0.6  0.5  0.4  0.35 0.3  0.25

Base rate: configurable (default 100 flows/sec for dev, 1000+ for load test)
```

---

## Attack Patterns

### 1. Port Scan

**Signature:** One source → one target → many ports, very short connections

```
Parameters:
  src_ip: attacker (external or compromised internal)
  target_ip: victim
  ports_scanned: 50-1000 (configurable)
  scan_type: SYN (half-open), Connect (full), FIN (stealth)
  inter-probe_delay: 1-50ms (fast scan) or 1-5s (slow/evasive)

Generated Flow Characteristics:
  duration: 0.0001 - 0.01s (very short)
  bytes_fwd: 40-60 (SYN packet only)
  bytes_bwd: 0-44 (RST or nothing)
  packets_fwd: 1
  packets_bwd: 0-1
  tcp_flags: SYN only (no ACK, possible RST response)
  payload_entropy: 0.0 (no payload)
```

### 2. SYN Flood (DDoS)

**Signature:** Many spoofed sources → one target, SYN-only, massive rate

```
Parameters:
  target_ip: victim server
  target_port: 80 or 443 (web service)
  rate: 1000-50000 packets/sec
  duration: 10-300 seconds
  spoofed_sources: random IPs (never seen before)

Generated Flow Characteristics:
  duration: 0.0 (never completes)
  bytes_fwd: 44 (bare SYN)
  bytes_bwd: 0 (no response reaches spoofed IP)
  packets_fwd: 1
  packets_bwd: 0
  tcp_flags: {SYN: 1, ACK: 0} exclusively
  payload_entropy: 0.0
  
Detection Signals:
  - packets_per_second to single dst > 5000
  - SYN ratio > 95%
  - Many unique src_ips never seen before
  - Uniform packet size (all 44 bytes)
```

### 3. Brute Force (SSH/RDP/FTP)

**Signature:** Same src → same dst:port, repeated short connections, auth failures

```
Parameters:
  src_ip: attacker
  target_ip: server with auth service
  service_port: 22 (SSH), 3389 (RDP), 21 (FTP)
  attempts: 20-500
  inter_attempt_delay: 0.5-5s (human-like)

Generated Flow Characteristics:
  duration: 0.5-3.0s (connect, try creds, get rejected)
  bytes_fwd: 100-300 (username + password attempt)
  bytes_bwd: 50-150 (authentication failure response)
  packets_fwd: 3-8
  packets_bwd: 2-6
  tcp_flags: SYN + ACK + PSH + FIN (normal TCP lifecycle)
  payload_entropy: 4.0-5.5 (text-based auth)

Detection Signals:
  - connection_count_5m to same dst:port > 20
  - avg_duration < 3s (quick rejection)
  - Repeated pattern (same flow shape)
```

### 4. C2 Beaconing

**Signature:** Periodic callbacks from infected host to external server, very regular timing

```
Parameters:
  infected_ip: compromised internal host
  c2_server: external IP (attacker infrastructure)
  beacon_interval: 30-300 seconds
  jitter: ±10% of interval
  beacon_count: 10-100+

Generated Flow Characteristics:
  duration: 0.5-2.0s (short check-in)
  bytes_fwd: 200-500 (very uniform size — encoded commands)
  bytes_bwd: 100-800 (responses vary slightly)
  dst_port: 443 (disguised as HTTPS)
  packets_fwd: 2-5
  packets_bwd: 2-5
  payload_entropy: 7.2-7.9 (encrypted = high entropy)
  
Detection Signals:
  - periodicity_score > 0.85 (regular timing detected via FFT)
  - Single consistent dst_ip over long period
  - Very uniform bytes_fwd (±20 bytes variation)
  - High payload entropy (encrypted channel)
```

### 5. Lateral Movement

**Signature:** Internal host suddenly connecting to many internal hosts on admin/management ports

```
Parameters:
  compromised_ip: internal host (after initial compromise)
  targets: 3-10 other internal hosts
  ports: [22, 445, 3389, 5985, 135, 139] (admin/management)
  inter_target_delay: 5-30s

Generated Flow Characteristics:
  duration: 1-30s (varies by what they're doing)
  bytes_fwd: 500-5000
  bytes_bwd: 200-3000
  dst_port: admin ports (22=SSH, 445=SMB, 3389=RDP, 5985=WinRM)
  packets_fwd: 5-30
  packets_bwd: 3-20
  payload_entropy: 5.0-7.5

Detection Signals:
  - Internal → internal on admin ports (unusual for this host)
  - new_dst_ips spike (connecting to hosts never contacted before)
  - Host role mismatch (workstation shouldn't SSH to database)
```

### 6. DNS Tunneling

**Signature:** Data exfiltration through encoded DNS queries — abnormally long/frequent DNS traffic

```
Parameters:
  infected_ip: compromised host
  dns_server: internal DNS resolver
  queries: 50-500
  query_rate: 1-10 per second

Generated Flow Characteristics:
  duration: 0.01-0.1s (DNS is fast)
  bytes_fwd: 80-255 (encoded data in query subdomain)
  bytes_bwd: 100-512 (TXT record response with encoded data)
  dst_port: 53 (DNS)
  protocol: UDP
  packets_fwd: 1
  packets_bwd: 1
  payload_entropy: 7.0-7.95 (base64/hex encoded = very high)

Detection Signals:
  - dns_query_entropy > 7.0 (normal DNS names have lower entropy)
  - bytes_fwd > 80 per DNS query (normal queries are ~40-60 bytes)
  - dns_query_count_1h abnormally high
  - Single source generating excessive DNS volume
```

### 7. Data Exfiltration

**Signature:** Large sustained outbound transfer to unusual/rare external destination

```
Parameters:
  src_ip: internal host with access to sensitive data
  dst_ip: attacker-controlled external server (rare/new IP)
  total_data: 10-500 MB
  chunk_size: 50KB-500KB per flow

Generated Flow Characteristics:
  duration: derived from chunk_size / bandwidth
  bytes_fwd: 50,000-500,000 per chunk (very large outbound)
  bytes_bwd: 100-1000 (just TCP ACKs)
  dst_port: 443 or 8443 (disguised as HTTPS)
  packets_fwd: chunk / 1460 (many packets)
  packets_bwd: ~50% of fwd (ACK batching)
  payload_entropy: 7.5-8.0 (encrypted = max entropy)

Detection Signals:
  - bytes_fwd_1h > 3 standard deviations above mean for this host
  - Destination never seen before in network history
  - Massive fwd/bwd asymmetry (sending >> receiving)
  - Long sustained transfer to single external IP
```

---

## Multi-Step Attack Scenarios

### APT Kill Chain (Full Lifecycle)

```
Timeline:
  T+0min:     External recon — port scan (50 ports, slow scan)
  T+5min:     Initial access — SSH brute force (30 attempts)
  T+8min:     Establish persistence — C2 beacon starts (60s interval)
  T+10min:    Internal recon — lateral port scan from compromised host
  T+15min:    Lateral movement — pivot to 3 internal hosts
  T+25min:    Data staging — access database server
  T+30min:    Exfiltration — 50 MB transfer to external server
  T+35min:    Cleanup — short burst of unusual admin commands

Total duration: ~35 minutes
Total flows generated: ~500-1000
```

### Drive-By + Botnet Recruitment

```
Timeline:
  T+0min:     Exploit delivery — single suspicious HTTP download
  T+1min:     C2 registration — first beacon to botnet controller
  T+2min:     C2 beaconing — regular 120s interval callbacks
  T+30min:    Lateral scan — infected host scans internal subnet
  T+45min:    Second infection — another host begins beaconing
  T+60min:    DDoS participation — both hosts flood external target
```

### Insider Threat

```
Timeline:
  T+0min:     Normal work hours — regular traffic patterns
  T+18:00:    After hours — access to file shares (unusual time)
  T+18:15:    Large internal download — pulling data from NAS
  T+18:30:    Staging — data compressed (brief CPU spike in traffic patterns)
  T+19:00:    Exfiltration — slow trickle to personal cloud storage
  T+19:30:    Cleanup — delete access logs (admin port connections)
```

---

## Using the Generator

### CLI Commands

```bash
# Generate normal traffic only
netguard generate --profile normal --rate 500 --duration 300 --output ./data/normal.jsonl

# Generate specific attack
netguard generate --attack port_scan --count 1000 --output ./data/scan.jsonl
netguard generate --attack syn_flood --rate 5000 --duration 30 --output ./data/ddos.jsonl
netguard generate --attack brute_force --attempts 50 --service ssh --output ./data/brute.jsonl

# Generate mixed traffic (normal + injected attacks)
netguard generate --profile mixed --attack-ratio 0.05 --rate 1000 --duration 600 --output ./data/mixed.jsonl

# Run multi-step scenario
netguard generate --scenario apt_kill_chain --output ./data/apt.jsonl
netguard generate --scenario botnet_recruitment --output ./data/botnet.jsonl

# Output to Kafka (for integration testing)
netguard generate --profile mixed --attack-ratio 0.03 --output kafka://localhost:9092/raw-flows

# Replay CICIDS2017 dataset
netguard replay --input ./data/cicids2017/ --format cicids --speed 100x --output kafka://localhost:9092/flows
```

### Python API

```python
from netguard.testing import NetworkTrafficGenerator, AttackGenerator, AttackScenario

# Normal traffic
gen = NetworkTrafficGenerator(seed=42)
async for flow in gen.stream(rate=100, include_attacks=False):
    process(flow)

# Specific attack
attacks = AttackGenerator(gen)
async for flow in attacks.generate_port_scan(target_ip="10.0.1.50", ports=100):
    process(flow)

# Full scenario
scenario = AttackScenario(attacks)
async for flow in scenario.apt_kill_chain():
    process(flow)
```

---

## Datasets Supported for Replay

### CICIDS2017 (Primary)

| Property | Value |
|----------|-------|
| Size | ~7 GB (CSV) |
| Flows | 2.8M+ labeled |
| Duration | 5 days of traffic |
| Labels | Benign, DoS, PortScan, Brute Force, Web Attack, Botnet, Infiltration |
| Download | [UNB CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) |

### NSL-KDD (Legacy)

| Property | Value |
|----------|-------|
| Size | ~150 MB |
| Records | 150K (train) + 22K (test) |
| Labels | Normal, DoS, Probe, R2L, U2R |
| Use | Good for quick model prototyping |

### UNSW-NB15

| Property | Value |
|----------|-------|
| Size | ~1.7 GB |
| Records | 2.5M flows |
| Labels | 9 attack categories |
| Use | Modern attacks, good feature diversity |

---

## Output Formats

The generator can output to:

| Format | Flag | Use Case |
|--------|------|----------|
| JSON Lines | `--output ./file.jsonl` | Analysis, replay, debugging |
| CSV | `--output ./file.csv` | Jupyter notebooks, pandas |
| Kafka | `--output kafka://host:port/topic` | Integration testing |
| Stdout | `--output -` | Piping to other tools |
| Parquet | `--output ./file.parquet` | Large dataset, efficient storage |

### JSON Lines Schema (per flow)

```json
{
  "timestamp": 1720000000.123,
  "src_ip": "10.0.1.45",
  "dst_ip": "203.0.113.50",
  "src_port": 52341,
  "dst_port": 443,
  "protocol": "TCP",
  "duration": 1.234,
  "bytes_fwd": 1520,
  "bytes_bwd": 45230,
  "packets_fwd": 12,
  "packets_bwd": 35,
  "tcp_flags": {"SYN": 1, "ACK": 30, "FIN": 1, "RST": 0, "PSH": 8, "URG": 0},
  "payload_entropy": 6.82,
  "label": "benign",
  "attack_type": null
}
```
