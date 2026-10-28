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
"""

import json
import sys
import os
import io
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.engine import PerfRCAAgent
from agent.log_analyzer import analyze_logs

HOST = "127.0.0.1"
PORT = 8080
MAX_PAYLOAD_BYTES = 5_000_000

agent = PerfRCAAgent()
current_logs = None  # holds uploaded logs in memory for analysis

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


class RequestHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        print(f"[API] {args[0]}" if args else fmt, flush=True)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/":
            self._serve_frontend()
        elif path == "/api/memory":
            self._handle_memory_get()
        elif path == "/api/logs/download":
            self._handle_logs_download()
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

        # Inject custom logs into the agent for this investigation
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

    def _handle_memory_get(self):
        cases = agent.memory.list_cases()
        self._json_response(200, {"cases": cases, "count": len(cases)})

    # ── API: Download logs ────────────────────────────────────────────

    def _handle_logs_download(self):
        """Download the demo log file as a .log text file."""
        logs_path = PROJECT_ROOT / "fixtures" / "logs.json"
        if not logs_path.exists():
            self._json_response(404, {"error": "Log file not found"})
            return
        with open(logs_path, "r", encoding="utf-8") as f:
            logs = json.load(f)

        # Format as human-readable log lines
        lines = []
        for entry in logs:
            ts = entry.get("timestamp", "")
            lvl = entry.get("level", "INFO")
            svc = entry.get("service", "")
            msg = entry.get("message", "")
            lines.append(f"{ts} [{lvl:5s}] {svc}: {msg}")

        body = "\n".join(lines)
        self._text_response(200, body, "text/plain; charset=utf-8", "auth-service.log")

    # ── API: Upload logs ──────────────────────────────────────────────

    def _handle_logs_upload(self):
        """Accept a JSON array or text log file, parse it, analyze, and return results."""
        global current_logs
        raw = self._read_body()
        if raw is None:
            return

        content_type = self.headers.get("Content-Type", "")

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except Exception:
                self._json_response(400, {"error": "Unable to decode file. Upload UTF-8 text or JSON."})
                return

        # Try parsing as JSON array first
        parsed = None
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            pass

        if isinstance(parsed, list) and len(parsed) > 0 and isinstance(parsed[0], dict):
            # JSON log format
            entries = parsed
        else:
            # Try parsing as text log lines
            entries = []
            for line in text.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                # Common log formats: timestamp level message OR level: message
                entry = {"message": line}
                # Try ISO timestamp prefix
                if len(line) > 20 and line[4] == "-" and line[7] == "-":
                    parts = line.split(" ", 1) if " " in line else (line, "")
                    entry["timestamp"] = parts[0]
                    rest = parts[1] if len(parts) > 1 else ""
                    # Try extracting level
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

        # Validate
        if not entries:
            self._json_response(400, {"error": "No log entries found in uploaded file."})
            return
        if len(entries) > 50000:
            self._json_response(400, {"error": "Too many log entries. Maximum 50,000 allowed."})
            return

        # Analyze
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


def run_server(host=HOST, port=PORT):
    server = HTTPServer((host, port), RequestHandler)
    print(f"Perf RCA server running at http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    run_server()