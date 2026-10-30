"""Tests for PlatformStore, ConnectorRegistry, parsers, and metrics_engine."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from store import PlatformStore
from connectors import ConnectorRegistry, ConnectorStatus
from agent.parsers import (
    parse_json_log, parse_text_line, parse_nginx_line, parse_logfmt_line,
    normalize_entries, search_entries,
)
from agent.metrics_engine import (
    generate_time_series, get_metrics_summary,
    get_anomaly_intervals, export_metrics_csv,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

BASELINE = {
    "run_id": "baseline-test-01",
    "service": "test-svc",
    "timestamp": "2026-10-25T10:00:00Z",
    "metrics": {
        "latency": {"p50_ms": 45, "p95_ms": 120, "p99_ms": 250, "mean_ms": 52},
        "throughput": {"requests_per_second": 850},
        "error_rate": {"percentage": 0.1, "total_errors": 255},
        "resources": {"cpu_percent": 45, "memory_gb": 2.1},
    },
}

CURRENT = {
    "run_id": "current-test-01",
    "service": "test-svc",
    "timestamp": "2026-10-27T09:00:00Z",
    "metrics": {
        "latency": {"p50_ms": 200, "p95_ms": 600, "p99_ms": 950, "mean_ms": 250},
        "throughput": {"requests_per_second": 300},
        "error_rate": {"percentage": 5.5, "total_errors": 1650},
        "resources": {"cpu_percent": 90, "memory_gb": 3.8},
    },
}


# ── PlatformStore Tests ───────────────────────────────────────────────────────

class TestPlatformStoreIncidents(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        db_path = Path(self.tmpdir) / "test.db"
        self.store = PlatformStore(db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_incident_returns_dict(self):
        inc = self.store.create_incident("Test incident", service="auth-service")
        self.assertIsInstance(inc, dict)
        self.assertEqual(inc["title"], "Test incident")

    def test_create_incident_has_id(self):
        inc = self.store.create_incident("Test", service="svc")
        self.assertIn("id", inc)
        self.assertTrue(len(inc["id"]) > 0)

    def test_create_incident_default_status_open(self):
        inc = self.store.create_incident("Test")
        self.assertEqual(inc["status"], "open")

    def test_get_incident_returns_correct(self):
        inc = self.store.create_incident("My incident", service="svc-a", severity="critical")
        fetched = self.store.get_incident(inc["id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["title"], "My incident")
        self.assertEqual(fetched["service"], "svc-a")
        self.assertEqual(fetched["severity"], "critical")

    def test_get_incident_not_found(self):
        result = self.store.get_incident("nonexistent-id")
        self.assertIsNone(result)

    def test_list_incidents_empty(self):
        result = self.store.list_incidents()
        self.assertEqual(result, [])

    def test_list_incidents_returns_all(self):
        self.store.create_incident("A")
        self.store.create_incident("B")
        result = self.store.list_incidents()
        self.assertEqual(len(result), 2)

    def test_list_incidents_filter_status(self):
        inc = self.store.create_incident("A")
        self.store.create_incident("B")
        self.store.update_incident_status(inc["id"], "resolved")
        result = self.store.list_incidents({"status": "resolved"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["status"], "resolved")

    def test_list_incidents_filter_severity(self):
        self.store.create_incident("A", severity="critical")
        self.store.create_incident("B", severity="low")
        result = self.store.list_incidents({"severity": "critical"})
        self.assertEqual(len(result), 1)

    def test_list_incidents_filter_service(self):
        self.store.create_incident("A", service="auth-service")
        self.store.create_incident("B", service="payment-service")
        result = self.store.list_incidents({"service": "auth-service"})
        self.assertEqual(len(result), 1)

    def test_update_incident_status(self):
        inc = self.store.create_incident("Test")
        updated = self.store.update_incident_status(inc["id"], "acknowledged")
        self.assertEqual(updated["status"], "acknowledged")

    def test_add_incident_event_returns_dict(self):
        inc = self.store.create_incident("Test")
        event = self.store.add_incident_event(inc["id"], "created", actor="admin", message="Created")
        self.assertIsInstance(event, dict)
        self.assertEqual(event["event_type"], "created")

    def test_get_incident_timeline(self):
        inc = self.store.create_incident("Test")
        self.store.add_incident_event(inc["id"], "created", actor="user1")
        self.store.add_incident_event(inc["id"], "acknowledged", actor="user2")
        timeline = self.store.get_incident_timeline(inc["id"])
        self.assertEqual(len(timeline), 2)

    def test_get_incident_timeline_empty(self):
        inc = self.store.create_incident("Test")
        timeline = self.store.get_incident_timeline(inc["id"])
        self.assertEqual(timeline, [])


class TestPlatformStoreAlerts(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        db_path = Path(self.tmpdir) / "test_alerts.db"
        self.store = PlatformStore(db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_create_alert_returns_dict(self):
        alert = self.store.create_alert("High latency", service="auth-service",
                                        condition_metric="latency_p99_ms",
                                        threshold=500.0, operator=">", severity="critical")
        self.assertIsInstance(alert, dict)
        self.assertEqual(alert["name"], "High latency")

    def test_create_alert_has_id(self):
        alert = self.store.create_alert("Test alert")
        self.assertIn("id", alert)

    def test_list_alerts_empty(self):
        result = self.store.list_alerts()
        self.assertEqual(result, [])

    def test_list_alerts_returns_all(self):
        self.store.create_alert("Alert A")
        self.store.create_alert("Alert B")
        result = self.store.list_alerts()
        self.assertEqual(len(result), 2)

    def test_list_alerts_filter_service(self):
        self.store.create_alert("A", service="auth-service")
        self.store.create_alert("B", service="payment-service")
        result = self.store.list_alerts(service="auth-service")
        self.assertEqual(len(result), 1)

    def test_fire_alert_updates_status(self):
        alert = self.store.create_alert("Test")
        fired = self.store.fire_alert(alert["id"])
        self.assertEqual(fired["status"], "firing")
        self.assertIsNotNone(fired["last_fired_at"])


class TestPlatformStoreCases(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        db_path = Path(self.tmpdir) / "test_cases.db"
        self.store = PlatformStore(db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_case_returns_dict(self):
        case = self.store.save_case("rca-001", service="auth-service",
                                    symptoms={"latency": "high"},
                                    fingerprint={"metric": "latency_p99_ms"})
        self.assertIsInstance(case, dict)
        self.assertEqual(case["investigation_id"], "rca-001")

    def test_save_case_default_status_pending(self):
        case = self.store.save_case("rca-002")
        self.assertEqual(case["status"], "pending")

    def test_confirm_case(self):
        case = self.store.save_case("rca-003", service="auth-service")
        confirmed = self.store.confirm_case(case["id"], confirmed_by="admin", fix_applied="Reverted commit")
        self.assertEqual(confirmed["status"], "confirmed")
        self.assertEqual(confirmed["confirmed_by"], "admin")
        self.assertEqual(confirmed["fix_applied"], "Reverted commit")

    def test_list_cases_empty(self):
        result = self.store.list_cases()
        self.assertEqual(result, [])

    def test_list_cases_returns_all(self):
        self.store.save_case("rca-1")
        self.store.save_case("rca-2")
        result = self.store.list_cases()
        self.assertEqual(len(result), 2)

    def test_search_cases_by_symptom(self):
        self.store.save_case("rca-1", service="auth-service",
                              symptoms={"latency": "high", "error": "timeout"})
        self.store.save_case("rca-2", service="auth-service",
                              symptoms={"cpu": "spiking"})
        result = self.store.search_cases_by_symptom(symptom_keyword="timeout")
        self.assertEqual(len(result), 1)

    def test_search_cases_by_service(self):
        self.store.save_case("rca-1", service="auth-service")
        self.store.save_case("rca-2", service="payment-service")
        result = self.store.search_cases_by_symptom(service="auth-service")
        self.assertEqual(len(result), 1)


class TestPlatformStoreSavedSearches(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        db_path = Path(self.tmpdir) / "test_searches.db"
        self.store = PlatformStore(db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_save_search_returns_dict(self):
        s = self.store.save_search("My search", query="timeout", filters={"severity": "ERROR"})
        self.assertIsInstance(s, dict)
        self.assertEqual(s["name"], "My search")

    def test_list_saved_searches_empty(self):
        result = self.store.list_saved_searches()
        self.assertEqual(result, [])

    def test_list_saved_searches_returns_all(self):
        self.store.save_search("Search A")
        self.store.save_search("Search B")
        result = self.store.list_saved_searches()
        self.assertEqual(len(result), 2)

    def test_saved_search_filters_parsed(self):
        self.store.save_search("Test", filters={"severity": "ERROR", "service": "auth"})
        result = self.store.list_saved_searches()
        self.assertIsInstance(result[0]["filters"], dict)
        self.assertEqual(result[0]["filters"]["severity"], "ERROR")


class TestPlatformStorePing(unittest.TestCase):
    def test_ping_healthy_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = PlatformStore(Path(tmpdir) / "ping_test.db")
            self.assertTrue(store.ping())


# ── ConnectorRegistry Tests ───────────────────────────────────────────────────

class TestConnectorRegistry(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        # Ensure no env vars that would configure connectors
        self._original_env = {}
        for key in ("PROMETHEUS_URL", "ES_URL", "JAEGER_URL", "GITHUB_TOKEN",
                    "JIRA_URL", "JIRA_TOKEN", "CONFLUENCE_URL", "CONFLUENCE_TOKEN",
                    "ALERTMANAGER_URL"):
            self._original_env[key] = os.environ.pop(key, None)
        self.registry = ConnectorRegistry(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        for key, val in self._original_env.items():
            if val is not None:
                os.environ[key] = val

    def test_list_all_statuses_returns_seven(self):
        statuses = self.registry.list_all_statuses()
        self.assertEqual(len(statuses), 7)

    def test_list_all_statuses_connector_names(self):
        statuses = self.registry.list_all_statuses()
        names = {s["name"] for s in statuses}
        expected = {"prometheus", "elasticsearch", "jaeger", "github",
                    "jira", "confluence", "alertmanager"}
        self.assertEqual(names, expected)

    def test_unconfigured_connectors_show_false(self):
        statuses = self.registry.list_all_statuses()
        for s in statuses:
            self.assertFalse(s["configured"], f"{s['name']} should not be configured")

    def test_get_status_returns_connector_status(self):
        status = self.registry.get_status("prometheus")
        self.assertIsNotNone(status)
        self.assertEqual(status.name, "prometheus")
        self.assertFalse(status.configured)

    def test_get_status_unknown_connector(self):
        result = self.registry.get_status("nonexistent")
        self.assertIsNone(result)

    def test_test_connector_unconfigured_returns_not_ok(self):
        result = self.registry.test_connector("prometheus")
        self.assertFalse(result["ok"])
        self.assertIn("not configured", result["message"].lower())

    def test_test_connector_unknown_returns_not_ok(self):
        result = self.registry.test_connector("unknown-connector")
        self.assertFalse(result["ok"])

    def test_status_has_required_fields(self):
        statuses = self.registry.list_all_statuses()
        required = {"name", "type", "configured", "healthy", "last_check",
                    "error", "config_keys_present"}
        for s in statuses:
            self.assertEqual(set(s.keys()), required, f"Missing fields in {s['name']}")

    def test_configured_connector_when_env_set(self):
        os.environ["PROMETHEUS_URL"] = "http://prometheus.example.com"
        try:
            registry = ConnectorRegistry(self.tmpdir)
            status = registry.get_status("prometheus")
            self.assertTrue(status.configured)
        finally:
            del os.environ["PROMETHEUS_URL"]

    def test_ssrf_blocks_private_and_loopback_urls(self):
        from connectors import _is_private_url
        self.assertTrue(_is_private_url("http://127.0.0.1:9090"))
        self.assertTrue(_is_private_url("http://localhost:8080"))
        self.assertTrue(_is_private_url("http://10.0.1.5:9090"))
        self.assertTrue(_is_private_url("http://192.168.1.100:9200"))
        self.assertTrue(_is_private_url("http://172.16.0.1:9090"))
        self.assertTrue(_is_private_url("http://service.internal:8080"))

    def test_ssrf_allows_public_url(self):
        from connectors import _is_private_url
        self.assertFalse(_is_private_url("https://api.github.com"))


# ── Parsers Tests ─────────────────────────────────────────────────────────────

class TestParseJsonLog(unittest.TestCase):
    def test_basic_json_log(self):
        entry = {
            "timestamp": "2026-10-27T09:15:00Z",
            "level": "ERROR",
            "service": "auth-service",
            "message": "Timeout acquiring connection",
        }
        result = parse_json_log(entry)
        self.assertEqual(result["timestamp"], "2026-10-27T09:15:00Z")
        self.assertEqual(result["severity"], "ERROR")
        self.assertEqual(result["service"], "auth-service")
        self.assertEqual(result["message"], "Timeout acquiring connection")

    def test_severity_normalization(self):
        result = parse_json_log({"level": "WARNING", "message": "test"})
        self.assertEqual(result["severity"], "WARN")

    def test_unknown_severity(self):
        result = parse_json_log({"level": "VERBOSE", "message": "test"})
        self.assertEqual(result["severity"], "UNKNOWN")

    def test_structured_fields_captured(self):
        entry = {"level": "INFO", "message": "ok", "request_count": 100, "latency": 50}
        result = parse_json_log(entry)
        self.assertIn("request_count", result["structured_fields"])
        self.assertIn("latency", result["structured_fields"])

    def test_trace_id_extracted(self):
        entry = {"level": "INFO", "message": "ok", "trace_id": "abc123"}
        result = parse_json_log(entry)
        self.assertEqual(result["trace_id"], "abc123")

    def test_has_all_canonical_fields(self):
        result = parse_json_log({"message": "test"})
        for field in ("id", "timestamp", "severity", "service", "environment",
                      "host", "source", "message", "structured_fields",
                      "trace_id", "span_id", "request_id", "exception_type",
                      "stack_trace", "original", "parse_error"):
            self.assertIn(field, result)


class TestParseTextLine(unittest.TestCase):
    def test_basic_text_line(self):
        line = "2026-10-27T09:15:00Z ERROR auth-service: Connection timeout"
        result = parse_text_line(line)
        self.assertIn("2026-10-27", result["timestamp"])
        self.assertEqual(result["severity"], "ERROR")

    def test_info_level(self):
        line = "2026-10-27T09:00:00Z INFO test: All good"
        result = parse_text_line(line)
        self.assertEqual(result["severity"], "INFO")

    def test_no_timestamp_sets_parse_error(self):
        line = "ERROR Something went wrong"
        result = parse_text_line(line)
        self.assertEqual(result["parse_error"], "no_timestamp")

    def test_service_message_extracted(self):
        line = "2026-10-27T09:00:00Z INFO myservice: Hello world"
        result = parse_text_line(line)
        self.assertEqual(result["service"], "myservice")
        self.assertEqual(result["message"], "Hello world")

    def test_returns_canonical_schema(self):
        result = parse_text_line("some log line")
        self.assertIn("severity", result)
        self.assertIn("message", result)
        self.assertIn("original", result)
        self.assertIn("status", result)

    def test_python_traceback_extraction(self):
        line = "2026-10-27T09:15:00Z ERROR worker: Traceback (most recent call last):\nZeroDivisionError: division by zero"
        result = parse_text_line(line)
        self.assertEqual(result["exception_type"], "ZeroDivisionError")
        self.assertEqual(result["severity"], "ERROR")
        self.assertIsNotNone(result["stack_trace"])

    def test_java_exception_extraction(self):
        line = "2026-10-27T09:15:00Z ERROR PaymentGateway: java.lang.NullPointerException: Transaction failed"
        result = parse_text_line(line)
        self.assertEqual(result["exception_type"], "java.lang.NullPointerException")
        self.assertEqual(result["severity"], "ERROR")

    def test_status_flag_parsed_and_partial(self):
        clean = parse_text_line("2026-10-27T09:00:00Z INFO s: msg")
        self.assertEqual(clean["status"], "parsed")
        bad = parse_text_line("Broken line without timestamp")
        self.assertEqual(bad["status"], "partial")


class TestParseNginxLine(unittest.TestCase):
    def test_basic_nginx_line(self):
        line = '1.2.3.4 - - [27/Oct/2026:09:15:00 +0000] "GET /health HTTP/1.1" 200 512 "-" "curl/7.68"'
        result = parse_nginx_line(line)
        self.assertEqual(result["severity"], "INFO")
        self.assertIn("GET /health", result["message"])

    def test_nginx_500_is_error(self):
        line = '1.2.3.4 - - [27/Oct/2026:09:15:00 +0000] "POST /api HTTP/1.1" 500 0 "-" "client/1.0"'
        result = parse_nginx_line(line)
        self.assertEqual(result["severity"], "ERROR")

    def test_nginx_404_is_warn(self):
        line = '1.2.3.4 - - [27/Oct/2026:09:15:00 +0000] "GET /missing HTTP/1.1" 404 0 "-" "client/1.0"'
        result = parse_nginx_line(line)
        self.assertEqual(result["severity"], "WARN")

    def test_nginx_parse_failed(self):
        line = "this is not nginx format"
        result = parse_nginx_line(line)
        self.assertIsNotNone(result["parse_error"])

    def test_nginx_structured_fields(self):
        line = '1.2.3.4 - - [27/Oct/2026:09:15:00 +0000] "GET /path HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        result = parse_nginx_line(line)
        self.assertIn("remote_addr", result["structured_fields"])
        self.assertEqual(result["structured_fields"]["remote_addr"], "1.2.3.4")


class TestNormalizeEntries(unittest.TestCase):
    def test_normalize_json_entries(self):
        raw = [
            {"level": "ERROR", "message": "error one", "timestamp": "2026-10-27T09:00:00Z"},
            {"level": "INFO", "message": "all good", "timestamp": "2026-10-27T09:01:00Z"},
        ]
        result = normalize_entries(raw, source="test")
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["parse_errors"], 0)
        self.assertEqual(result["skipped"], 0)

    def test_normalize_skips_none(self):
        raw = [None, {"message": "ok"}, None]
        result = normalize_entries(raw, source="test")
        self.assertEqual(result["skipped"], 2)
        self.assertEqual(result["total"], 1)

    def test_normalize_returns_entries_list(self):
        raw = [{"message": "test"}]
        result = normalize_entries(raw, source="test_source")
        self.assertIn("entries", result)
        self.assertIsInstance(result["entries"], list)

    def test_normalize_sets_source(self):
        raw = [{"message": "test"}]
        result = normalize_entries(raw, source="my_source")
        self.assertEqual(result["entries"][0]["source"], "my_source")

    def test_normalize_empty_list(self):
        result = normalize_entries([], source="test")
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["entries"], [])


class TestSearchEntries(unittest.TestCase):
    def _sample_entries(self):
        raw = [
            {"level": "ERROR", "service": "auth-service", "message": "connection timeout", "timestamp": "2026-10-27T09:00:00Z"},
            {"level": "INFO", "service": "auth-service", "message": "request succeeded", "timestamp": "2026-10-27T09:01:00Z"},
            {"level": "ERROR", "service": "payment-service", "message": "payment failed", "timestamp": "2026-10-27T09:02:00Z"},
            {"level": "WARN", "service": "auth-service", "message": "slow query detected", "timestamp": "2026-10-27T09:03:00Z"},
        ]
        return normalize_entries(raw, source="test")["entries"]

    def test_keyword_match(self):
        entries = self._sample_entries()
        result = search_entries(entries, keyword="timeout")
        self.assertEqual(result["total"], 1)
        self.assertIn("timeout", result["results"][0]["message"])

    def test_keyword_case_insensitive(self):
        entries = self._sample_entries()
        result = search_entries(entries, keyword="TIMEOUT")
        self.assertEqual(result["total"], 1)

    def test_filter_by_severity(self):
        entries = self._sample_entries()
        result = search_entries(entries, filters={"severity": "ERROR"})
        self.assertEqual(result["total"], 2)

    def test_filter_by_service(self):
        entries = self._sample_entries()
        result = search_entries(entries, filters={"service": "payment-service"})
        self.assertEqual(result["total"], 1)

    def test_pagination(self):
        entries = self._sample_entries()
        result = search_entries(entries, page=1, page_size=2)
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["total"], 4)

    def test_no_keyword_returns_all(self):
        entries = self._sample_entries()
        result = search_entries(entries)
        self.assertEqual(result["total"], 4)

    def test_no_match_returns_empty(self):
        entries = self._sample_entries()
        result = search_entries(entries, keyword="zzznomatch")
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["results"], [])

    def test_combined_keyword_and_filter(self):
        entries = self._sample_entries()
        result = search_entries(entries, keyword="timeout", filters={"service": "auth-service"})
        self.assertEqual(result["total"], 1)

    def test_page_number_in_result(self):
        entries = self._sample_entries()
        result = search_entries(entries, page=1, page_size=10)
        self.assertEqual(result["page"], 1)

    def test_filters_then_paginates(self):
        # Verify it searches ALL entries, not just a page
        entries = self._sample_entries()
        result = search_entries(entries, filters={"severity": "ERROR"}, page=1, page_size=1)
        self.assertEqual(result["total"], 2)  # 2 ERROR entries total
        self.assertEqual(len(result["results"]), 1)  # page_size=1

    def test_search_by_timestamp_bounds(self):
        entries = self._sample_entries()
        result = search_entries(entries, filters={"from": "2026-10-27T09:00:30Z", "to": "2026-10-27T09:02:30Z"})
        self.assertEqual(result["total"], 2)

    def test_search_by_status(self):
        entries = self._sample_entries()
        result = search_entries(entries, filters={"status": "parsed"})
        self.assertEqual(result["total"], 4)


# ── Metrics Engine Tests ──────────────────────────────────────────────────────

class TestGenerateTimeSeries(unittest.TestCase):
    def test_returns_correct_point_count(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms", n_points=60)
        self.assertEqual(len(series), 60)

    def test_custom_point_count(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms", n_points=30)
        self.assertEqual(len(series), 30)

    def test_returns_list_of_dicts(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms")
        self.assertIsInstance(series, list)
        if series:
            self.assertIsInstance(series[0], dict)

    def test_each_point_has_required_fields(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms")
        for point in series:
            self.assertIn("timestamp", point)
            self.assertIn("value", point)
            self.assertIn("is_baseline", point)

    def test_is_baseline_flag_correct(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms", n_points=60)
        half = 30
        for i, point in enumerate(series):
            if i < half:
                self.assertTrue(point["is_baseline"])
            else:
                self.assertFalse(point["is_baseline"])

    def test_unknown_metric_returns_empty(self):
        series = generate_time_series(BASELINE, CURRENT, "nonexistent_metric_xyz")
        self.assertEqual(series, [])

    def test_values_are_numeric(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms")
        for point in series:
            self.assertIsInstance(point["value"], (int, float))

    def test_alias_metric_key(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99")  # alias
        self.assertGreater(len(series), 0)

    def test_throughput_series(self):
        series = generate_time_series(BASELINE, CURRENT, "throughput_rps")
        self.assertGreater(len(series), 0)


class TestExportMetricsCsv(unittest.TestCase):
    def test_has_header(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms", n_points=5)
        csv_data = export_metrics_csv(series, "latency_p99_ms")
        first_line = csv_data.split("\n")[0]
        self.assertIn("timestamp", first_line)
        self.assertIn("value", first_line)
        self.assertIn("metric", first_line)

    def test_correct_row_count(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms", n_points=10)
        csv_data = export_metrics_csv(series, "latency_p99_ms")
        lines = [l for l in csv_data.strip().split("\n") if l]
        # 1 header + 10 data rows
        self.assertEqual(len(lines), 11)

    def test_metric_name_in_rows(self):
        series = generate_time_series(BASELINE, CURRENT, "latency_p99_ms", n_points=3)
        csv_data = export_metrics_csv(series, "latency_p99_ms")
        for line in csv_data.strip().split("\n")[1:]:
            self.assertIn("latency_p99_ms", line)

    def test_empty_series(self):
        csv_data = export_metrics_csv([], "latency_p99_ms")
        lines = [l for l in csv_data.strip().split("\n") if l]
        self.assertEqual(len(lines), 1)  # just the header


class TestGetMetricsSummary(unittest.TestCase):
    def test_returns_dict(self):
        summary = get_metrics_summary(BASELINE, CURRENT)
        self.assertIsInstance(summary, dict)

    def test_has_latency_p99(self):
        summary = get_metrics_summary(BASELINE, CURRENT)
        self.assertIn("latency_p99_ms", summary)

    def test_has_required_metric_keys(self):
        summary = get_metrics_summary(BASELINE, CURRENT)
        expected_keys = {"latency_p99_ms", "throughput_rps", "error_rate_pct",
                         "cpu_percent", "memory_gb"}
        for key in expected_keys:
            self.assertIn(key, summary, f"Missing metric key: {key}")

    def test_each_metric_has_required_fields(self):
        summary = get_metrics_summary(BASELINE, CURRENT)
        required_fields = {"display_name", "baseline", "current", "percent_change",
                           "severity", "unit"}
        for key, val in summary.items():
            for field in required_fields:
                self.assertIn(field, val, f"Missing field '{field}' in metric '{key}'")

    def test_severity_is_valid(self):
        summary = get_metrics_summary(BASELINE, CURRENT)
        valid_severities = {"ok", "low", "medium", "high", "critical"}
        for key, val in summary.items():
            self.assertIn(val["severity"], valid_severities)

    def test_percent_change_calculation(self):
        summary = get_metrics_summary(BASELINE, CURRENT)
        # latency_p99_ms: 250 -> 950 = 280% increase
        pct = summary["latency_p99_ms"]["percent_change"]
        self.assertIsNotNone(pct)
        self.assertGreater(pct, 200)


class TestGetAnomalyIntervals(unittest.TestCase):
    def _make_series(self, values):
        from datetime import datetime, timezone, timedelta
        base_dt = datetime(2026, 10, 27, 9, 0, 0, tzinfo=timezone.utc)
        return [
            {"timestamp": (base_dt + timedelta(minutes=i)).isoformat(), "value": v}
            for i, v in enumerate(values)
        ]

    def test_no_anomaly_when_all_normal(self):
        series = self._make_series([100, 102, 99, 101, 100])
        intervals = get_anomaly_intervals(series, baseline_val=100, threshold_pct=20.0)
        self.assertEqual(intervals, [])

    def test_detects_anomaly(self):
        # Values spike above 20% threshold
        values = [100, 100, 200, 250, 200, 100, 100]
        series = self._make_series(values)
        intervals = get_anomaly_intervals(series, baseline_val=100, threshold_pct=20.0)
        self.assertGreater(len(intervals), 0)

    def test_anomaly_interval_has_required_fields(self):
        values = [100, 100, 200, 200, 100]
        series = self._make_series(values)
        intervals = get_anomaly_intervals(series, baseline_val=100, threshold_pct=20.0)
        if intervals:
            for interval in intervals:
                self.assertIn("start", interval)
                self.assertIn("end", interval)
                self.assertIn("max_deviation_pct", interval)

    def test_empty_series_returns_empty(self):
        intervals = get_anomaly_intervals([], baseline_val=100)
        self.assertEqual(intervals, [])

    def test_zero_baseline_returns_empty(self):
        series = self._make_series([10, 20, 30])
        intervals = get_anomaly_intervals(series, baseline_val=0)
        self.assertEqual(intervals, [])


if __name__ == "__main__":
    unittest.main()
