# Perf RCA — AI Performance Root Cause Analysis

An AI agent that analyzes performance test failures: detects anomalies against baselines, investigates root-cause hypotheses, cites supporting and contradictory evidence, identifies suspected commits, proposes fixes, and verifies through retesting.

## Quick Start

```bash
# Run the server
python server.py

# In another terminal, run the tests
python -m pytest tests/test_agent.py -v
```

Open **http://127.0.0.1:8080** in your browser. Click **Demo Investigation** to run a pre-loaded regression analysis.

## Architecture

```
demo_dashboard/
├── index.html              # Frontend dashboard (HTML, CSS, vanilla JS)
├── server.py               # HTTP API server (Python 3 stdlib)
├── agent/
│   ├── __init__.py
│   ├── engine.py           # Core agent engine with bounded workflow
│   ├── anomaly.py          # Explainable baseline-vs-current comparisons
│   ├── log_analyzer.py     # Log pattern grouping, error-spike detection
│   └── memory.py           # Local JSON memory store for RCA cases
├── fixtures/
│   ├── baseline.json       # Sample baseline performance run
│   ├── current_run.json    # Current run with planted regression
│   ├── commits.json        # Commit metadata for attribution
│   └── logs.json           # Timestamped log entries with error spikes
├── memory/                 # Persisted RCA case memory (JSON)
├── tests/
│   ├── __init__.py
│   └── test_agent.py       # 54 tests for all modules
└── README.md
```

## Agent Workflow

1. **Validate** the investigation request (mode, payload size, URL safety)
2. **Load** baseline and current-run metric data, commits, and logs
3. **Detect anomalies** using percentage-change comparisons with severity labeling (low/medium/high/critical)
4. **Analyze logs** — group patterns, count frequencies, detect error bursts, correlate timestamps
5. **Generate hypotheses** from severe anomalies, correlating with commit history and log evidence
6. **Evaluate hypotheses** — boost/penalize confidence based on supporting and contradictory evidence
7. **Produce report** with ranked hypotheses, evidence, fix recommendations, Jira/Confluence previews
8. **Retest simulation** — deterministic estimate of metrics after proposed fix

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/investigate` | Run full RCA investigation |
| `POST` | `/api/retest` | Run simulated retest |
| `GET` | `/api/memory` | List stored RCA cases |
| `GET` | `/` | Serve the dashboard |

### POST /api/investigate

```json
{ "mode": "demo" }
```

Returns: `{ run_id, status, steps_taken, observations, report: { hypotheses, anomalies, recommendations, fix_verification, jira_preview, confluence_preview } }`

## Demo Scenario

The pre-loaded fixtures demonstrate a **thread pool exhaustion** regression:

- **Baseline**: auth-service with 32 threads, P99 latency 250ms, 0.1% errors
- **Current**: auth-service with 24 threads (commit `a1b2c3d`), P99 latency 620ms, 2.8% errors
- **Root cause**: Thread pool reduction from 32→24 creates head-of-line blocking. Retry logic (commit `e4f5g6h`) amplifies load.
- **Recommended fix**: Restore thread_pool_size to 32; add circuit breaker to retry logic

## Assumptions and Limitations

- **Deterministic only**: No external LLM required. The default demo uses rule-based hypothesis generation and evaluation.
- **Simulated retest**: Fix verification is a deterministic estimate, not a real deployment. Clearly labeled as simulated.
- **Local fixtures**: Data is loaded from JSON files. No live dashboard or database connections.
- **Confidence is computed**: Based on percentage change magnitude, commit evidence overlap, and contradictory evidence — not calibrated AI certainty.
- **Git attribution**: Commit metadata is loaded from `fixtures/commits.json`. Real Git history inspection would require a configured adapter.
- **No external URLs**: Default demo runs entirely offline. Grafana URL integration is gated behind configurable adapters.

## Security Controls

- Input validation: payload size limit (1 MB), dangerous key rejection
- URL sanitization: blocks `javascript:`, `data:`, and other unsafe schemes
- Path traversal prevention on static file serving
- Read-only JSON fixture loading
- No shell execution, no arbitrary filesystem access
- Prompt-injection resistant: deterministic output never labeled as LLM-generated
- CORS headers for development; restrict in production

## How to Measure

Time-to-root-cause, top-1 RCA accuracy, and engineer effort can be measured using **planted benchmark cases**. Create a known regression (e.g., reduce thread pool size), run Perf RCA against it, and measure:
- **TTR**: wall-clock time from investigation start to report delivery
- **Accuracy**: whether the top-ranked hypothesis matches the planted cause
- **Engineer effort saved**: time spent manually inspecting dashboards and logs vs. reviewing the RCA report

## License

Proprietary — SDSI Hackathon Round 2