# PR: Perf RCA — AI Performance Root Cause Analysis Agent

## Title
PerfRCA: AI-driven performance regression investigation with anomaly detection, hypothesis evaluation, and evidence-backed root cause analysis

## Implementation

- **Frontend**: Single-page HTML dashboard with metric tiles, anomaly cards, confidence-ranked hypothesis display, SVG sparklines, log evidence viewer, recommendations grid, and Jira/Confluence preview cards
- **Backend**: Python 3 `http.server` with JSON API endpoints (`/api/investigate`, `/api/retest`, `/api/memory`)
- **Agent engine**: Bounded state machine (validate → load → analyze → hypothesize → evaluate → report) with 7 explicit states, step tracking, honest outcome reporting
- **Anomaly detection**: Percentage-change comparisons with severity classification (low/medium/high/critical), zero-baseline handling, robust statistics
- **Log analysis**: Pattern grouping with request-ID normalization, error burst detection, frequency counting
- **Memory store**: Local JSON-backed case storage with explainable fingerprint similarity matching

## Test Evidence

- **54 tests**, all passing (`python -m pytest tests/test_agent.py -v`)
- Coverage: anomaly detection (11), log analysis (8), memory store (5), agent engine (21), prompt injection (2), integration (7)
- Key scenarios: regression detection, false-positive guard, zero baselines, missing data, empty inputs, malicious URLs, honest outcome labels

## Known Gaps

- Grafana URL fetching requires a configurable adapter (stubbed for demo)
- LLM integration for hypothesis generation is gated behind an optional adapter
- Real Jira/Confluence ticket creation requires configured credentials
- Retest is simulated; real retest needs a controlled performance test environment
- Git history inspection is file-based; real `git log` would need a subprocess adapter
- No persistent database — memory store is JSON files

## Security

- Payload size limit (1 MB), dangerous key rejection
- URL sanitization (blocks javascript:, data: schemes)
- Path traversal prevention on static file serving
- No shell execution or arbitrary filesystem access
- Deterministic output never labeled as LLM-generated
- Read-only fixture loading

🤖 Generated with [Claude Code](https://claude.com/claude-code)