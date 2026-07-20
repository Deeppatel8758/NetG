# NetGuard Documentation

## Real-Time Network Intrusion Detection System

A plug-and-play, open-source NIDS using stream processing (Kafka) + online ML models with adaptive thresholds.

---

## Document Index

| # | Document | Description |
|---|----------|-------------|
| 00 | [Overview](./00-overview.md) | Project goals, problem statement, tech stack, quick start |
| 01 | [Architecture](./01-architecture.md) | System architecture, data flow, component responsibilities |
| 02 | [Resource Requirements](./02-resource-requirements.md) | Hardware specs, costs, scaling rules for all tiers |
| 03 | [ML Models](./03-ml-models.md) | Model architectures, training, features, ensemble logic |
| 04 | [Data Generation](./04-data-generation.md) | Synthetic traffic, attack patterns, test data strategy |
| 05 | [Plugin System](./05-plugin-system.md) | Extensibility, custom adapters/models/outputs |
| 06 | [Implementation Phases](./06-implementation-phases.md) | Week-by-week build plan with tasks and verification |
| 07 | [Deployment Guide](./07-deployment-guide.md) | Docker Compose, K8s, production setup |
| 08 | [API Reference](./08-api-reference.md) | REST API endpoints, request/response schemas |

---

## Quick Phase Summary

| Phase | Duration | What You Build | Key Outcome |
|-------|----------|---------------|-------------|
| **Phase 1** | Week 1-2 | Infrastructure + Generator + Streaming | Data flows end-to-end |
| **Phase 2** | Week 3-4 | Feature extraction + Redis store | 45 features per flow in real-time |
| **Phase 3** | Week 5-6 | 3 ML models + Ensemble + Threshold | Anomaly scoring working |
| **Phase 4** | Week 7 | Rules + Threat Intel + Alerts | Attacks detected and routed |
| **Phase 5** | Week 8 | REST API + Grafana dashboards | Observable and queryable |
| **Phase 6** | Week 9-10 | Polish + Tests + PyPI release | Open source ready |

---

## Resource Quick Reference

| Tier | Use Case | Hardware | Cost | Throughput |
|------|----------|----------|------|-----------|
| Dev | Your laptop | 8 cores, 16 GB RAM | $0 | 1K flows/s |
| Small Prod | Small office (1-5 Gbps) | 3 nodes, 48 GB total | ~$725/mo | 10K flows/s |
| Enterprise | Large network (10-40 Gbps) | K8s cluster, 500+ GB RAM | ~$10K/mo | 100K flows/s |

---

## Start Here

1. Read [00-overview.md](./00-overview.md) for the big picture
2. Read [06-implementation-phases.md](./06-implementation-phases.md) for what to build and when
3. Start Phase 1: set up Docker, build the generator, get Kafka streaming
