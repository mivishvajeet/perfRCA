"""Perf RCA — HTTP API Server.

Endpoints:
  POST /api/investigate     — Run a full RCA investigation.
  POST /api/retest          — Run a simulated retest.
  GET  /api/memory          — List stored RCA cases.
  GET  /api/logs/download   — Download the current run's log file.
  POST /api/logs/upload     — Upload a custom log file and analyze it.
  GET  /api/db-metrics      — Get DB scenario metrics.
  GET  /api/scenarios       — List available demo scenarios.
  GET  /                    — Serve frontend HTML.

  GET  /api/health                   — Service health check.
  GET  /api/connectors/status        — List connector statuses.
  POST /api/connectors/test          — Test a specific connector.
  GET  /api/incidents                — List incidents (filter: status, severity, service).
  GET  /api/incidents/{id}           — Get single incident.
  GET  /api/incidents/{id}/timeline  — Get incident timeline.
  POST /api/incidents                — Create incident.
  POST /api/incidents/{id}/acknowledge  — Acknowledge incident.
  POST /api/incidents/{id}/resolve      — Resolve incident.
  POST /api/incidents/{id}/reopen       — Reopen incident.
  POST /api/incidents/{id}/link-investigation — Link RCA to incident.
  GET  /api/alerts                   — List alerts.
  POST /api/alerts                   — Create alert.
  GET  /api/logs/search              — Search log entries.
  GET  /api/logs/patterns            — Get error patterns from logs.
  GET  /api/metrics/summary          — Metrics summary from fixture data.
  GET  /api/metrics/series           — Time-series data for a metric.
  GET  /api/metrics/anomalies        — Anomaly intervals.
  GET  /api/metrics/export           — Download metrics CSV.
  GET  /api/deployments              — List commits from fixtures.
  GET  /api/cases                    — List stored cases.
  GET  /api/cases/search             — Search cases by symptom.
  POST /api/cases/{id}/confirm       — Confirm a root cause case.
  GET  /api/saved-searches           — List saved searches.
  POST /api/saved-searches           — Save a search.
  GET  /api/traces                   — Return fixture trace data.
"""

import json
import sys
import os
import io
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.engine import PerfRCAAgent
from agent.log_analyzer import analyze_logs
from store import PlatformStore
from connectors import ConnectorRegistry
from agent.parsers import normalize_entries, search_entries
from agent.metrics_engine import (
    generate_time_series, get_metrics_summary,
    get_anomaly_intervals, export_metrics_csv,
)

HOST = os.environ.get("PERF_RCA_HOST", "0.0.0.0")
PORT = int(os.environ.get("PERF_RCA_PORT", "8080"))
MAX_PAYLOAD_BYTES = 5_000_000

_SERVER_START_TIME = time.monotonic()

agent = PerfRCAAgent()
current_logs = None  # holds uploaded logs in memory for analysis
store = PlatformStore(PROJECT_ROOT / "platform.db")
connectors = ConnectorRegistry(PROJECT_ROOT)

STATIC_DIR = PROJECT_ROOT

MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}

# Keys that are never allowed in request bodies
_DANGEROUS_KEY_PATTERNS = ("__", "exec", "eval", "import", "os.", "sys.")


def _is_dangerous_key(key: str) -> bool:
    key_lower = key.lower()
    return any(p in key_lower for p in _DANGEROUS_KEY_PATTERNS)


class RequestHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[API] {args[0]}" if args else fmt, flush=True)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        # ── Static / frontend ──────────────────────────────────────────
        if path == "/":
            self._serve_frontend()

        # ── Platform API ───────────────────────────────────────────────
        elif path == "/api/health":
            self._handle_health()

        elif path == "/api/connectors/status":
            self._handle_connectors_status()

        elif path == "/api/incidents":
            self._handle_incidents_list(qs)

        elif path.startswith("/api/incidents/"):
            parts = path.split("/")
            # /api/incidents/{id} or /api/incidents/{id}/timeline
            if len(parts) == 4:
                self._handle_incident_get(parts[3])
            elif len(parts) == 5 and parts[4] == "timeline":
                self._handle_incident_timeline(parts[3])
            else:
                self._json_response(404, {"error": "Not found", "path": path})

        elif path == "/api/alerts":
            self._handle_alerts_list(qs)

        elif path == "/api/logs/search":
            self._handle_logs_search(qs)

        elif path == "/api/logs/patterns":
            self._handle_logs_patterns()

        elif path == "/api/logs/download":
            self._handle_logs_download()

        elif path == "/api/metrics/summary":
            self._handle_metrics_summary(qs)

        elif path == "/api/metrics/series":
            self._handle_metrics_series(qs)

        elif path == "/api/metrics/anomalies":
            self._handle_metrics_anomalies(qs)

        elif path == "/api/metrics/export":
            self._handle_metrics_export(qs)

        elif path == "/api/memory":
            self._handle_memory_get()

        elif path == "/api/deployments":
            self._handle_deployments()

        elif path == "/api/cases":
            self._handle_cases_list(qs)

        elif path == "/api/cases/search":
            self._handle_cases_search(qs)

        elif path == "/api/saved-searches":
            self._handle_saved_searches_list()

        elif path == "/api/traces":
            self._handle_traces()

        elif path == "/api/db-metrics":
            self._handle_db_metrics()

        elif path == "/api/scenarios":
            self._handle_scenarios()

        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
        else:
            self._serve_static(path.lstrip("/"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/investigate":
            self._handle_investigate()
        elif path == "/api/retest":
            self._handle_retest()
        elif path == "/api/logs/upload":
            self._handle_logs_upload()
        elif path == "/api/connectors/test":
            self._handle_connectors_test()
        elif path == "/api/incidents":
            self._handle_incidents_create()
        elif path == "/api/alerts":
            self._handle_alerts_create()
        elif path == "/api/saved-searches":
            self._handle_saved_searches_create()

        elif path.startswith("/api/incidents/"):
            parts = path.split("/")
            # /api/incidents/{id}/acknowledge|resolve|reopen|link-investigation
            if len(parts) == 5:
                incident_id = parts[3]
                action = parts[4]
                if action == "acknowledge":
                    self._handle_incident_acknowledge(incident_id)
                elif action == "resolve":
                    self._handle_incident_resolve(incident_id)
                elif action == "reopen":
                    self._handle_incident_reopen(incident_id)
                elif action == "link-investigation":
                    self._handle_incident_link_investigation(incident_id)
                else:
                    self._json_response(404, {"error": "Unknown action", "path": path})
            else:
                self._json_response(404, {"error": "Not found", "path": path})

        elif path.startswith("/api/cases/"):
            parts = path.split("/")
            # /api/cases/{id}/confirm
            if len(parts) == 5 and parts[4] == "confirm":
                self._handle_case_confirm(parts[3])
            else:
                self._json_response(404, {"error": "Not found", "path": path})

        else:
            self._json_response(404, {"error": "Not found", "path": path})

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def _cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, status, data):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text_response(self, status, body, content_type="text/plain; charset=utf-8", filename=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self._cors_headers()
        self.send_header("Content-Type", content_type)
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_PAYLOAD_BYTES:
            self._json_response(413, {"error": "Payload too large", "max_bytes": MAX_PAYLOAD_BYTES})
            return None
        if length == 0:
            return {}
        return self.rfile.read(length)

    def _parse_json_body(self):
        raw = self._read_body()
        if raw is None:
            return None
        if isinstance(raw, dict):
            return raw
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self._json_response(400, {"error": "Invalid JSON", "detail": str(e)})
            return None

    def _validate_body(self, body):
        """Reject dangerous keys. Returns True if safe."""
        if not isinstance(body, dict):
            self._json_response(400, {"error": "Request body must be a JSON object."})
            return False
        dangerous_keys = [k for k in body if _is_dangerous_key(k)]
        if dangerous_keys:
            self._json_response(400, {"error": "Invalid request keys detected.", "keys": dangerous_keys})
            return False
        return True

    def _qs_first(self, qs, key, default=None):
        vals = qs.get(key, [])
        return vals[0] if vals else default

    def _serve_frontend(self):
        html_path = PROJECT_ROOT / "index.html"
        if not html_path.exists():
            self._json_response(404, {"error": "Frontend not found"})
            return
        content = html_path.read_bytes()
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_static(self, rel_path):
        safe_path = os.path.normpath(rel_path).lstrip(os.sep).lstrip("\\")
        if ".." in safe_path.split(os.sep):
            self._json_response(403, {"error": "Path traversal blocked"})
            return
        file_path = STATIC_DIR / safe_path
        if not file_path.is_file():
            self._json_response(404, {"error": "File not found", "path": rel_path})
            return
        ext = file_path.suffix.lower()
        mime = MIME_TYPES.get(ext, "application/octet-stream")
        content = file_path.read_bytes()
        self.send_response(200)
        self._cors_headers()
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    # ── API: Health ───────────────────────────────────────────────────

    def _handle_health(self):
        db_ok = store.ping()
        self._json_response(200, {
            "status": "ok",
            "version": "2.0.0",
            "uptime_seconds": round(time.monotonic() - _SERVER_START_TIME, 2),
            "db": "ok" if db_ok else "error",
        })

    # ── API: Connectors ───────────────────────────────────────────────

    def _handle_connectors_status(self):
        statuses = connectors.list_all_statuses()
        # Never expose token values — strip them from response
        for s in statuses:
            s.pop("token", None)
            s.pop("password", None)
        self._json_response(200, {"connectors": statuses})

    def _handle_connectors_test(self):
        body = self._parse_json_body()
        if body is None:
            return
        if not self._validate_body(body):
            return
        connector_name = body.get("connector", "")
        if not connector_name:
            self._json_response(400, {"error": "Missing 'connector' field."})
            return
        result = connectors.test_connector(connector_name)
        self._json_response(200, result)

    # ── API: Incidents ────────────────────────────────────────────────

    def _handle_incidents_list(self, qs):
        filters = {}
        for key in ("status", "severity", "service"):
            val = self._qs_first(qs, key)
            if val:
                filters[key] = val
        incidents = store.list_incidents(filters)
        self._json_response(200, {"incidents": incidents, "count": len(incidents)})

    def _handle_incident_get(self, incident_id):
        incident = store.get_incident(incident_id)
        if incident is None:
            self._json_response(404, {"error": f"Incident '{incident_id}' not found."})
            return
        self._json_response(200, incident)

    def _handle_incident_timeline(self, incident_id):
        incident = store.get_incident(incident_id)
        if incident is None:
            self._json_response(404, {"error": f"Incident '{incident_id}' not found."})
            return
        timeline = store.get_incident_timeline(incident_id)
        self._json_response(200, {"incident_id": incident_id, "events": timeline, "count": len(timeline)})

    def _handle_incidents_create(self):
        body = self._parse_json_body()
        if body is None:
            return
        if not self._validate_body(body):
            return
        title = body.get("title", "").strip()
        if not title:
            self._json_response(400, {"error": "Missing required field: 'title'."})
            return
        incident = store.create_incident(
            title=title,
            service=body.get("service"),
            severity=body.get("severity", "medium"),
            description=body.get("description"),
            owner=body.get("owner"),
        )
        if incident is None:
            self._json_response(500, {"error": "Failed to create incident."})
            return
        store.add_incident_event(incident["id"], "created",
                                  actor=body.get("owner", "system"),
                                  message=f"Incident created: {title}")
        self._json_response(201, incident)

    def _handle_incident_acknowledge(self, incident_id):
        body = self._parse_json_body()
        if body is None:
            body = {}
        incident = store.get_incident(incident_id)
        if incident is None:
            self._json_response(404, {"error": f"Incident '{incident_id}' not found."})
            return
        updated = store.update_incident_status(incident_id, "acknowledged")
        store.add_incident_event(incident_id, "acknowledged",
                                  actor=body.get("actor", "system"),
                                  message=body.get("message", "Incident acknowledged."))
        self._json_response(200, updated)

    def _handle_incident_resolve(self, incident_id):
        body = self._parse_json_body()
        if body is None:
            body = {}
        incident = store.get_incident(incident_id)
        if incident is None:
            self._json_response(404, {"error": f"Incident '{incident_id}' not found."})
            return
        extra = {}
        if body.get("resolution"):
            extra["description"] = body["resolution"]
        updated = store.update_incident_status(incident_id, "resolved", extra)
        store.add_incident_event(incident_id, "resolved",
                                  actor=body.get("actor", "system"),
                                  message=body.get("message", "Incident resolved."))
        self._json_response(200, updated)

    def _handle_incident_reopen(self, incident_id):
        body = self._parse_json_body()
        if body is None:
            body = {}
        incident = store.get_incident(incident_id)
        if incident is None:
            self._json_response(404, {"error": f"Incident '{incident_id}' not found."})
            return
        updated = store.update_incident_status(incident_id, "open")
        store.add_incident_event(incident_id, "reopened",
                                  actor=body.get("actor", "system"),
                                  message=body.get("message", "Incident reopened."))
        self._json_response(200, updated)

    def _handle_incident_link_investigation(self, incident_id):
        body = self._parse_json_body()
        if body is None:
            return
        if not self._validate_body(body):
            return
        investigation_id = body.get("investigation_id", "").strip()
        if not investigation_id:
            self._json_response(400, {"error": "Missing 'investigation_id'."})
            return
        incident = store.get_incident(incident_id)
        if incident is None:
            self._json_response(404, {"error": f"Incident '{incident_id}' not found."})
            return
        updated = store.update_incident_status(
            incident_id, incident["status"],
            extra={"rca_investigation_id": investigation_id}
        )
        store.add_incident_event(incident_id, "investigation_linked",
                                  actor="system",
                                  message=f"Linked RCA investigation: {investigation_id}")
        self._json_response(200, updated)

    # ── API: Alerts ───────────────────────────────────────────────────

    def _handle_alerts_list(self, qs):
        service = self._qs_first(qs, "service")
        alerts = store.list_alerts(service=service)
        self._json_response(200, {"alerts": alerts, "count": len(alerts)})

    def _handle_alerts_create(self):
        body = self._parse_json_body()
        if body is None:
            return
        if not self._validate_body(body):
            return
        name = body.get("name", "").strip()
        if not name:
            self._json_response(400, {"error": "Missing required field: 'name'."})
            return
        alert = store.create_alert(
            name=name,
            service=body.get("service"),
            condition_metric=body.get("condition_metric"),
            threshold=body.get("threshold"),
            operator=body.get("operator", ">"),
            severity=body.get("severity", "medium"),
            enabled=body.get("enabled", True),
        )
        if alert is None:
            self._json_response(500, {"error": "Failed to create alert."})
            return
        self._json_response(201, alert)

    # ── API: Logs ─────────────────────────────────────────────────────

    def _handle_logs_search(self, qs):
        global current_logs
        keyword = self._qs_first(qs, "q", "")
        severity = self._qs_first(qs, "severity")
        service = self._qs_first(qs, "service")
        environment = self._qs_first(qs, "environment")
        status = self._qs_first(qs, "status")
        from_ts = self._qs_first(qs, "from") or self._qs_first(qs, "from_ts") or self._qs_first(qs, "start")
        to_ts = self._qs_first(qs, "to") or self._qs_first(qs, "to_ts") or self._qs_first(qs, "end")
        try:
            page = int(self._qs_first(qs, "page", "1"))
        except ValueError:
            page = 1
        try:
            page_size = int(self._qs_first(qs, "page_size", "50"))
        except ValueError:
            page_size = 50

        # Use uploaded logs if available, else fixture logs
        raw_entries = current_logs
        source = "uploaded_json"
        if raw_entries is None:
            logs_path = PROJECT_ROOT / "fixtures" / "logs.json"
            if logs_path.exists():
                with open(logs_path, "r", encoding="utf-8") as f:
                    raw_entries = json.load(f)
                source = "json_fixture"
            else:
                raw_entries = []

        normalized = normalize_entries(raw_entries, source)
        entries = normalized["entries"]

        filters = {}
        if severity:
            filters["severity"] = severity
        if service:
            filters["service"] = service
        if environment:
            filters["environment"] = environment
        if status:
            filters["status"] = status
        if from_ts:
            filters["from"] = from_ts
        if to_ts:
            filters["to"] = to_ts

        result = search_entries(entries, keyword=keyword, filters=filters,
                                page=page, page_size=page_size)
        self._json_response(200, result)

    def _handle_logs_patterns(self):
        global current_logs
        raw_entries = current_logs
        if raw_entries is None:
            logs_path = PROJECT_ROOT / "fixtures" / "logs.json"
            if logs_path.exists():
                with open(logs_path, "r", encoding="utf-8") as f:
                    raw_entries = json.load(f)
            else:
                raw_entries = []

        analysis = analyze_logs(raw_entries)
        self._json_response(200, {
            "grouped_patterns": analysis.get("grouped_patterns", []),
            "new_patterns": analysis.get("new_patterns", []),
            "level_counts": analysis.get("level_counts", {}),
            "total_logs": analysis.get("total_logs", 0),
            "error_count": analysis.get("error_count", 0),
        })

    def _handle_logs_download(self):
        """Download the demo log file as a .log text file."""
        logs_path = PROJECT_ROOT / "fixtures" / "logs.json"
        if not logs_path.exists():
            self._json_response(404, {"error": "Log file not found"})
            return
        with open(logs_path, "r", encoding="utf-8") as f:
            logs = json.load(f)

        lines = []
        for entry in logs:
            ts = entry.get("timestamp", "")
            lvl = entry.get("level", "INFO")
            svc = entry.get("service", "")
            msg = entry.get("message", "")
            lines.append(f"{ts} [{lvl:5s}] {svc}: {msg}")

        body = "\n".join(lines)
        self._text_response(200, body, "text/plain; charset=utf-8", "auth-service.log")

    # ── API: Metrics ──────────────────────────────────────────────────

    def _load_scenario_fixtures(self, scenario="demo"):
        if scenario == "db":
            base_path = PROJECT_ROOT / "fixtures" / "baseline_db.json"
        else:
            base_path = PROJECT_ROOT / "fixtures" / "baseline.json"
        curr_path = PROJECT_ROOT / "fixtures" / "current_run.json"
        with open(base_path, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        with open(curr_path, "r", encoding="utf-8") as f:
            current = json.load(f)
        return baseline, current

    def _handle_metrics_summary(self, qs):
        scenario = self._qs_first(qs, "scenario", "demo")
        try:
            baseline, current = self._load_scenario_fixtures(scenario)
        except FileNotFoundError as e:
            self._json_response(404, {"error": f"Fixture not found: {e}"})
            return
        summary = get_metrics_summary(baseline, current)
        self._json_response(200, {"summary": summary, "scenario": scenario})

    def _handle_metrics_series(self, qs):
        metric = self._qs_first(qs, "metric", "latency_p99_ms")
        scenario = self._qs_first(qs, "scenario", "demo")
        try:
            n_points = int(self._qs_first(qs, "n", "60"))
        except ValueError:
            n_points = 60
        try:
            baseline, current = self._load_scenario_fixtures(scenario)
        except FileNotFoundError as e:
            self._json_response(404, {"error": f"Fixture not found: {e}"})
            return
        series = generate_time_series(baseline, current, metric, n_points=n_points)
        if not series:
            self._json_response(404, {"error": f"Unknown or unavailable metric: '{metric}'"})
            return
        self._json_response(200, {"metric": metric, "scenario": scenario, "series": series, "count": len(series)})

    def _handle_metrics_anomalies(self, qs):
        scenario = self._qs_first(qs, "scenario", "demo")
        metric = self._qs_first(qs, "metric", "latency_p99_ms")
        try:
            threshold = float(self._qs_first(qs, "threshold", "20.0"))
        except ValueError:
            threshold = 20.0
        try:
            baseline, current = self._load_scenario_fixtures(scenario)
        except FileNotFoundError as e:
            self._json_response(404, {"error": f"Fixture not found: {e}"})
            return
        series = generate_time_series(baseline, current, metric)
        from agent.metrics_engine import _get_nested, _resolve_metric_key, _METRIC_DEFS
        canonical = _resolve_metric_key(metric)
        defn = _METRIC_DEFS.get(canonical)
        if not defn:
            self._json_response(404, {"error": f"Unknown metric: '{metric}'"})
            return
        baseline_val = _get_nested(baseline, defn[0])
        if baseline_val is None:
            self._json_response(404, {"error": f"Metric '{metric}' not found in baseline fixture."})
            return
        intervals = get_anomaly_intervals(series, float(baseline_val), threshold_pct=threshold)
        self._json_response(200, {
            "metric": metric, "scenario": scenario,
            "threshold_pct": threshold, "intervals": intervals,
            "count": len(intervals),
        })

    def _handle_metrics_export(self, qs):
        metric = self._qs_first(qs, "metric", "latency_p99_ms")
        scenario = self._qs_first(qs, "scenario", "demo")
        try:
            baseline, current = self._load_scenario_fixtures(scenario)
        except FileNotFoundError as e:
            self._json_response(404, {"error": f"Fixture not found: {e}"})
            return
        series = generate_time_series(baseline, current, metric)
        if not series:
            self._json_response(404, {"error": f"Unknown or unavailable metric: '{metric}'"})
            return
        csv_data = export_metrics_csv(series, metric)
        filename = f"{metric}_{scenario}.csv"
        self._text_response(200, csv_data, "text/csv; charset=utf-8", filename)

    # ── API: Memory (legacy) ──────────────────────────────────────────

    def _handle_memory_get(self):
        cases = agent.memory.list_cases()
        self._json_response(200, {"cases": cases, "count": len(cases)})

    # ── API: Deployments ──────────────────────────────────────────────

    def _handle_deployments(self):
        commits_path = PROJECT_ROOT / "fixtures" / "commits.json"
        if not commits_path.exists():
            self._json_response(200, {"deployments": [], "count": 0})
            return
        with open(commits_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        commits = data.get("commit_metadata", {}).get("commits", [])
        service = data.get("service", "")
        self._json_response(200, {
            "deployments": commits,
            "count": len(commits),
            "service": service,
        })

    # ── API: Cases ────────────────────────────────────────────────────

    def _handle_cases_list(self, qs):
        filters = {}
        for key in ("service", "status"):
            val = self._qs_first(qs, key)
            if val:
                filters[key] = val
        cases = store.list_cases(filters)
        self._json_response(200, {"cases": cases, "count": len(cases)})

    def _handle_cases_search(self, qs):
        service = self._qs_first(qs, "service")
        symptom = self._qs_first(qs, "symptom")
        cases = store.search_cases_by_symptom(service=service, symptom_keyword=symptom)
        self._json_response(200, {"cases": cases, "count": len(cases)})

    def _handle_case_confirm(self, case_id):
        body = self._parse_json_body()
        if body is None:
            body = {}
        if body and not self._validate_body(body):
            return
        confirmed_by = body.get("confirmed_by", "system")
        fix_applied = body.get("fix_applied")
        case = store.confirm_case(case_id, confirmed_by=confirmed_by, fix_applied=fix_applied)
        if case is None:
            self._json_response(404, {"error": f"Case '{case_id}' not found."})
            return
        self._json_response(200, case)

    # ── API: Saved Searches ───────────────────────────────────────────

    def _handle_saved_searches_list(self):
        searches = store.list_saved_searches()
        self._json_response(200, {"saved_searches": searches, "count": len(searches)})

    def _handle_saved_searches_create(self):
        body = self._parse_json_body()
        if body is None:
            return
        if not self._validate_body(body):
            return
        name = body.get("name", "").strip()
        if not name:
            self._json_response(400, {"error": "Missing required field: 'name'."})
            return
        saved = store.save_search(
            name=name,
            query=body.get("query", ""),
            filters=body.get("filters", {}),
        )
        if saved is None:
            self._json_response(500, {"error": "Failed to save search."})
            return
        self._json_response(201, saved)

    # ── API: Traces ───────────────────────────────────────────────────

    def _handle_traces(self):
        traces_path = PROJECT_ROOT / "fixtures" / "traces.json"
        if traces_path.exists():
            with open(traces_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._json_response(200, data)
        else:
            # Stub response
            self._json_response(200, {
                "traces": [],
                "service_map": {"nodes": [], "edges": []},
                "message": "No trace data available. Connect a Jaeger instance for live traces.",
            })

    # ── API: Investigate ──────────────────────────────────────────────

    def _handle_investigate(self):
        body = self._parse_json_body()
        if body is None:
            return
        if not isinstance(body, dict):
            self._json_response(400, {"error": "Request body must be a JSON object."})
            return
        dangerous_keys = [k for k in body if k.startswith("__") or "exec" in k.lower() or "eval" in k.lower()]
        if dangerous_keys:
            self._json_response(400, {"error": "Invalid request keys detected."})
            return

        scenario = body.get("scenario", body.get("mode", "demo"))
        print(f"[API] Investigation requested: scenario={scenario}", flush=True)

        if current_logs is not None:
            agent._custom_logs = current_logs
        else:
            agent._custom_logs = None

        result = agent.investigate(body)
        status_code = 200 if result["status"] in ("completed", "partial") else 422
        self._json_response(status_code, result)

    def _handle_retest(self):
        body = self._parse_json_body()
        if body is None:
            body = {}
        result = agent.retest()
        self._json_response(200, result)

    # ── API: Upload logs ──────────────────────────────────────────────

    def _handle_logs_upload(self):
        """Accept a JSON array or text log file, parse it, analyze, and return results."""
        global current_logs
        raw = self._read_body()
        if raw is None:
            return

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except Exception:
                self._json_response(400, {"error": "Unable to decode file. Upload UTF-8 text or JSON."})
                return

        parsed = None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            pass

        if isinstance(parsed, list) and len(parsed) > 0 and isinstance(parsed[0], dict):
            entries = parsed
        else:
            entries = []
            for line in text.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                entry = {"message": line}
                if len(line) > 20 and line[4] == "-" and line[7] == "-":
                    parts = line.split(" ", 1) if " " in line else (line, "")
                    entry["timestamp"] = parts[0]
                    rest = parts[1] if len(parts) > 1 else ""
                    for lvl in ("ERROR", "WARN", "INFO", "DEBUG", "CRITICAL", "TRACE"):
                        if rest.strip().startswith(lvl):
                            rest2 = rest.strip()[len(lvl):].strip()
                            if rest2.startswith("]"):
                                rest2 = rest2[1:].strip()
                            entry["level"] = lvl
                            entry["message"] = rest2
                            break
                    if "level" not in entry:
                        entry["level"] = "INFO"
                        entry["message"] = rest
                elif ":" in line:
                    parts = line.split(":", 1)
                    prefix = parts[0].strip().upper()
                    for lvl in ("ERROR", "WARN", "INFO", "DEBUG", "CRITICAL", "TRACE"):
                        if lvl in prefix:
                            entry["level"] = lvl
                            entry["message"] = parts[1].strip() if len(parts) > 1 else ""
                            break
                    if "level" not in entry:
                        entry["level"] = "INFO"
                        entry["message"] = line
                else:
                    entry["level"] = "INFO"
                entries.append(entry)

        if not entries:
            self._json_response(400, {"error": "No log entries found in uploaded file."})
            return
        if len(entries) > 50000:
            self._json_response(400, {"error": "Too many log entries. Maximum 50,000 allowed."})
            return

        current_logs = entries
        analysis = analyze_logs(entries)

        self._json_response(200, {
            "message": f"Uploaded and analyzed {len(entries)} log entries.",
            "total_entries": len(entries),
            "analysis": analysis,
            "sample_entries": entries[:10]
        })

    # ── API: DB metrics scenario ──────────────────────────────────────

    def _handle_db_metrics(self):
        path = PROJECT_ROOT / "fixtures" / "db_scenario.json"
        if not path.exists():
            self._json_response(404, {"error": "DB scenario data not found"})
            return
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._json_response(200, data)

    # ── API: Scenarios list ───────────────────────────────────────────

    def _handle_scenarios(self):
        scenarios = [
            {
                "id": "demo",
                "name": "Thread Pool Exhaustion",
                "service": "auth-service",
                "description": "Thread pool reduced from 32→24 causes connection timeout cascade under load.",
                "severity": "high"
            },
            {
                "id": "db",
                "name": "Database Lock Contention",
                "service": "payment-db",
                "description": "New batch job with SELECT FOR UPDATE causes row-level lock contention and buffer pool thrashing.",
                "severity": "critical"
            }
        ]
        self._json_response(200, {"scenarios": scenarios})


class ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


def run_server(host=HOST, port=PORT):
    server = ReusableHTTPServer((host, port), RequestHandler)
    print(f"Perf RCA AI Platform server running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    run_server()
