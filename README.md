# perfRCA — Observability & Automated Root Cause Analysis Platform

An interactive, production-ready observability and automated incident investigation platform. Combines a log explorer, metrics dashboard, distributed tracing viewer, incident management system, and deterministic root-cause analysis workbench.

---

## ⚡ Quick Start

```bash
# Start the HTTP server (Python stdlib only, no pip install required)
python3 server.py

# In another terminal, run the complete test suite (175 tests across 4 test suites)
python3 -m unittest discover tests -v
```

Open **http://127.0.0.1:8080** in your browser.

---

## 🏗 Platform Architecture

```
perfRCA/
├── server.py               # Production HTTP API server with 30+ endpoints
├── store.py                # SQLite persistent store (incidents, alerts, searches, cases)
├── connectors.py           # Connector interfaces with SSRF protection & health probes
├── index.html              # Multi-workspace frontend SPA with persistent sidebar
├── dashboard.html          # Extended alternative dashboard view
├── pitch_deck.html         # Hackathon pitch presentation
├── agent/
│   ├── __init__.py
│   ├── engine.py           # Lead SRE Orchestrator coordinating the Multi-Agent Swarm
│   ├── metrics_agent.py    # 📊 MetricsAgent: Telemetry & Resource Saturation Specialist
│   ├── log_agent.py        # 📜 LogAgent: Log Pattern & Error Burst Mining Specialist
│   ├── git_agent.py        # 🚀 GitAgent: Code Change & Commit Attribution Specialist
│   ├── remediation_agent.py# 🔧 RemediationAgent: Fix Synthesis & Simulation Specialist
│   ├── anomaly.py          # Metric comparisons and severity classification
│   ├── log_analyzer.py     # Log pattern grouping & burst detection
│   ├── parsers.py          # Canonical log normalization & server-side search
│   ├── metrics_engine.py   # Time-series generation & anomaly intervals
│   └── memory.py           # Historical case memory store
├── fixtures/
│   ├── baseline.json       # Healthy run metrics (auth-service)
│   ├── current_run.json    # Regressed run with thread pool exhaustion
│   ├── baseline_db.json    # Healthy run metrics (payment-db)
│   ├── db_scenario.json    # DB lock contention scenario
│   ├── commits.json        # Git commit history for attribution
│   ├── logs.json           # Sample timestamped application logs
│   └── traces.json         # OpenTelemetry-compatible traces & service topology
└── tests/
    ├── __init__.py
    ├── test_agent.py       # 54 original engine & anomaly tests
    ├── test_platform.py    # 103 platform, store, connector, and parser tests
    ├── test_multi_agent.py # 12 multi-agent council and cognitive reasoning tests
    └── test_benchmark.py   # 6 known-incident benchmark evaluation tests
```

---

## 🎛 Workspaces & Capabilities

1. **Overview Dashboard**
   - Service health KPIs (P50/P95/P99 latency, throughput, error rate, CPU saturation)
   - Active incident queue and unresolved alerts
   - Recent deployments and configuration changes
   - Spiking error patterns and log bursts
   - Connector status and data freshness

2. **Universal Log Explorer**
   - Canonical normalization (JSON, timestamped text, Nginx, Logfmt)
   - Server-side keyword search & multi-severity filtering
   - Sorting, pagination, and expandable formatted event payloads
   - Grouped error patterns and sudden burst detection
   - CSV and JSON export of search results
   - Saved searches and reusable filters

3. **Metrics Explorer**
   - Interactive time-series charts (Chart.js)
   - Baseline vs current run regression overlay
   - Highlighted anomaly intervals (>20% deviation)
   - Metric drill-down to corresponding log intervals
   - CSV export for reporting

4. **Distributed Tracing & Service Map**
   - OpenTelemetry-compatible span waterfalls
   - Critical path duration breakdown with error & slow span highlights
   - Node-and-edge service dependency topology

5. **RCA Workbench**
   - Deterministic 7-stage bounded workflow
   - Heuristic confidence scoring with explicit factor breakdown
   - Supporting vs. contradictory evidence attribution
   - Suspected commit identification
   - Simulated fix verification (clearly labeled as non-production)
   - Actionable Jira ticket and Confluence postmortem draft previews

6. **Incident & Alert Management**
   - Persistent incident state machine (Open → Acknowledged → Resolved → Reopened)
   - Audited timeline event log for all transitions
   - Link RCA investigations directly to incidents
   - Configurable metric threshold alert rules

7. **Deployments & Change Intelligence**
   - Commit history timeline with changed files and diff summaries
   - Temporal correlation with regression windows

8. **Database Diagnostics**
   - Connection pool saturation and waiter queue depth
   - Row lock contention and deadlock frequency
   - Buffer pool efficiency and replication lag
   - Slow query sample inspections

9. **Historical Case Intelligence**
   - Persistent case memory with symptom fingerprinting
   - Recurrence detection via weighted Jaccard similarity
   - Explicit confirmation workflow for audited root causes

10. **Integrations & Connectors**
    - Connectors for Prometheus, Elasticsearch, Jaeger, GitHub, Jira, Confluence, Alertmanager
    - SSRF protection: blocks private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, localhost)
    - Server-side credential protection (tokens never sent to client)

---

## 🔌 API Reference

### Health & Connectors
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health probe & uptime |
| `GET` | `/api/connectors/status` | List integration connector statuses |
| `POST` | `/api/connectors/test` | Probe a specific connector connection |

### RCA & Retest
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/investigate` | Run 7-stage deterministic RCA investigation |
| `POST` | `/api/retest` | Run simulated fix verification |
| `GET` | `/api/memory` | Retrieve stored investigation results |

### Logs
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/logs/search` | Server-side log search with filters and pagination |
| `GET` | `/api/logs/patterns` | Grouped error patterns and burst detection |
| `GET` | `/api/logs/download` | Download sample fixture log file |
| `POST` | `/api/logs/upload` | Upload and analyze custom log file |

### Metrics & Traces
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/metrics/summary` | Baseline vs current metrics summary |
| `GET` | `/api/metrics/series` | Time-series data points with baseline |
| `GET` | `/api/metrics/anomalies` | Highlighted regression intervals |
| `GET` | `/api/metrics/export` | Download metric time-series as CSV |
| `GET` | `/api/traces` | Captured distributed traces & dependency map |
| `GET` | `/api/db-metrics` | Database performance metrics |

### Incidents, Alerts & Cases
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/incidents` | List filtered incidents |
| `POST` | `/api/incidents` | Create a new incident |
| `GET` | `/api/incidents/{id}/timeline` | Audit timeline of state changes |
| `POST` | `/api/incidents/{id}/acknowledge` | Acknowledge incident |
| `POST` | `/api/incidents/{id}/resolve` | Resolve incident with resolution note |
| `POST` | `/api/incidents/{id}/reopen` | Reopen resolved incident |
| `POST` | `/api/incidents/{id}/link-investigation` | Link RCA run ID to incident |
| `GET` | `/api/alerts` | List configured alert rules |
| `POST` | `/api/alerts` | Create new alert rule |
| `GET` | `/api/cases` | List confirmed RCA case history |
| `POST` | `/api/cases/{id}/confirm` | Audit confirm root cause and fix |

---

## 🧪 Testing & Verification

150 unit and integration tests covering the complete platform:

```bash
python3 -m unittest tests/test_agent.py tests/test_platform.py -v
```

All tests execute in ~0.15s using Python stdlib without external service requirements.

---

## 🔐 Security & Reliability

- **SSRF Protection:** External connector checks validate URLs against RFC 1918 private address ranges and loopback devices.
- **Input Sanitization:** Dangerous keys (`__`, `eval`, `exec`) are rejected at the HTTP gateway.
- **Safe Static Serving:** Path traversal (`..`) blocked in static file requests.
- **Credential Isolation:** API keys and connection tokens reside server-side in environment variables and are scrubbed from all API responses.
- **Deterministic Reliability:** Investigation logic operates without unpredictable third-party LLM dependencies.
