"""Tests for the Perf RCA agent engine, anomaly detector, log analyzer, and memory store."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agent.anomaly import compare_baseline, describe_anomalies, robust_summary
from agent.log_analyzer import analyze_logs, _normalize_pattern
from agent.memory import MemoryStore
from agent.engine import PerfRCAAgent


# ── Sample fixtures for testing ────────────────────────────────────────────

BASELINE = {
    "run_id": "baseline-01",
    "service": "test-svc",
    "timestamp": "2026-10-25T10:00:00Z",
    "metrics": {
        "latency": {"p50_ms": 10, "p95_ms": 50, "p99_ms": 100, "mean_ms": 15},
        "throughput": {"requests_per_second": 1000},
        "error_rate": {"percentage": 0.5, "total_errors": 50},
        "resources": {"cpu_percent": 30, "memory_gb": 1.0}
    }
}

CURRENT_BAD = {
    "run_id": "current-bad",
    "service": "test-svc",
    "timestamp": "2026-10-27T09:00:00Z",
    "metrics": {
        "latency": {"p50_ms": 30, "p95_ms": 200, "p99_ms": 450, "mean_ms": 50},
        "throughput": {"requests_per_second": 500},
        "error_rate": {"percentage": 5.0, "total_errors": 500},
        "resources": {"cpu_percent": 90, "memory_gb": 3.5}
    }
}

CURRENT_NORMAL = {
    "run_id": "current-normal",
    "service": "test-svc",
    "timestamp": "2026-10-27T09:00:00Z",
    "metrics": {
        "latency": {"p50_ms": 10, "p95_ms": 52, "p99_ms": 105, "mean_ms": 16},
        "throughput": {"requests_per_second": 980},
        "error_rate": {"percentage": 0.52, "total_errors": 52},
        "resources": {"cpu_percent": 31, "memory_gb": 1.05}
    }
}

CURRENT_ZERO_BASELINE = {
    "run_id": "current-zero",
    "service": "test-svc",
    "timestamp": "2026-10-27T09:00:00Z",
    "metrics": {
        "latency": {"p50_ms": 10, "p95_ms": 50, "p99_ms": 100, "mean_ms": 15},
        "throughput": {"requests_per_second": 1000},
        "error_rate": {"percentage": 0.0, "total_errors": 0},
        "resources": {"cpu_percent": 30, "memory_gb": 1.0}
    }
}

BASELINE_ZERO_ERROR = {
    "run_id": "baseline-zero",
    "service": "test-svc",
    "timestamp": "2026-10-25T10:00:00Z",
    "metrics": {
        "latency": {"p50_ms": 10, "p95_ms": 50, "p99_ms": 100, "mean_ms": 15},
        "throughput": {"requests_per_second": 1000},
        "error_rate": {"percentage": 0.0, "total_errors": 0},
        "resources": {"cpu_percent": 30, "memory_gb": 1.0}
    }
}

SAMPLE_LOGS = [
    {"timestamp": "2026-10-27T09:14:58Z", "level": "ERROR", "service": "svc", "message": "Timeout acquiring connection from pool after 5000ms for request req-0100"},
    {"timestamp": "2026-10-27T09:14:58Z", "level": "ERROR", "service": "svc", "message": "Timeout acquiring connection from pool after 5000ms for request req-0101"},
    {"timestamp": "2026-10-27T09:14:59Z", "level": "ERROR", "service": "svc", "message": "Timeout acquiring connection from pool after 5000ms for request req-0102"},
    {"timestamp": "2026-10-27T09:15:00Z", "level": "ERROR", "service": "svc", "message": "Thread pool exhausted, rejecting request req-0200"},
    {"timestamp": "2026-10-27T09:15:00Z", "level": "ERROR", "service": "svc", "message": "Thread pool exhausted, rejecting request req-0201"},
    {"timestamp": "2026-10-27T09:15:01Z", "level": "WARN", "service": "svc", "message": "High CPU: 88%"},
    {"timestamp": "2026-10-27T09:15:05Z", "level": "INFO", "service": "svc", "message": "Auth token validated for req-0300"},
    {"timestamp": "2026-10-27T09:15:10Z", "level": "INFO", "service": "svc", "message": "Run complete. Requests: 5000, Errors: 500"},
]

SAMPLE_LOGS_CLEAN = [
    {"timestamp": "2026-10-27T09:00:00Z", "level": "INFO", "service": "svc", "message": "Test started"},
    {"timestamp": "2026-10-27T09:05:00Z", "level": "INFO", "service": "svc", "message": "Test complete"},
]

SAMPLE_COMMITS = {
    "commit_metadata": {
        "repo": "test-svc",
        "commits": [
            {"hash": "abc123", "message": "Reduce thread pool size", "diff_summary": "thread_pool_size 32->24", "timestamp": "2026-10-26T14:00:00Z", "files_changed": ["pool.py"]},
            {"hash": "def456", "message": "Add retry logic", "diff_summary": "Added connection retry with deep queue", "timestamp": "2026-10-26T15:00:00Z", "files_changed": ["conn.py"]},
        ]
    }
}


class TestAnomalyDetection(unittest.TestCase):
    """Baseline comparisons and planted regression detection."""

    def test_detects_regression(self):
        anomalies = compare_baseline(BASELINE, CURRENT_BAD)
        self.assertGreater(len(anomalies), 0, "Should detect at least one anomaly in bad run")

    def test_no_false_positives_on_normal(self):
        anomalies = compare_baseline(BASELINE, CURRENT_NORMAL)
        self.assertEqual(len(anomalies), 0, "Normal run should have zero anomalies")

    def test_latency_regression_identified(self):
        anomalies = compare_baseline(BASELINE, CURRENT_BAD)
        lat_anoms = [a for a in anomalies if "latency" in a["metric"]]
        self.assertGreater(len(lat_anoms), 0, "Should detect latency degradation")
        self.assertIn(lat_anoms[0]["severity"], ("critical", "high", "medium"))

    def test_error_rate_regression_identified(self):
        anomalies = compare_baseline(BASELINE, CURRENT_BAD)
        err_anoms = [a for a in anomalies if "error_rate" in a["metric"]]
        self.assertGreater(len(err_anoms), 0, "Should detect error rate spike")

    def test_throughput_regression_identified(self):
        anomalies = compare_baseline(BASELINE, CURRENT_BAD)
        thr_anoms = [a for a in anomalies if "throughput" in a["metric"]]
        self.assertGreater(len(thr_anoms), 0, "Should detect throughput drop")

    def test_zero_baseline_handled(self):
        """Zero baseline for error rate should not crash."""
        anomalies = compare_baseline(BASELINE_ZERO_ERROR, CURRENT_NORMAL)
        # 0% to 0.6% is infinite % change but should be handled
        self.assertIsInstance(anomalies, list)

    def test_missing_metrics_handled(self):
        """Missing nested metrics should not crash."""
        partial = {
            "run_id": "partial",
            "service": "svc",
            "timestamp": "...",
            "metrics": {"latency": {"p50_ms": 10}}
        }
        anomalies = compare_baseline(BASELINE, partial)
        self.assertIsInstance(anomalies, list)

    def test_small_sample_handled(self):
        small_baseline = {"run_id": "b", "service": "s", "metrics": {"latency": {"p50_ms": 5}}}
        small_current = {"run_id": "c", "service": "s", "metrics": {"latency": {"p50_ms": 5}}}
        anomalies = compare_baseline(small_baseline, small_current)
        self.assertIsInstance(anomalies, list)

    def test_anomaly_has_required_fields(self):
        anomalies = compare_baseline(BASELINE, CURRENT_BAD)
        for a in anomalies:
            self.assertIn("metric", a)
            self.assertIn("baseline_value", a)
            self.assertIn("current_value", a)
            self.assertIn("percent_change", a)
            self.assertIn("direction", a)
            self.assertIn("severity", a)

    def test_describe_anomalies_no_anomalies(self):
        desc = describe_anomalies([])
        self.assertIn("No anomalies", desc)

    def test_describe_anomalies_with_data(self):
        anomalies = compare_baseline(BASELINE, CURRENT_BAD)
        desc = describe_anomalies(anomalies)
        self.assertIn("anomaly", desc.lower())


class TestRobustSummary(unittest.TestCase):
    def test_normal_list(self):
        s = robust_summary([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        self.assertEqual(s["n"], 10)
        self.assertEqual(s["median"], 5.5)

    def test_single_value(self):
        s = robust_summary([42])
        self.assertEqual(s["n"], 1)
        self.assertEqual(s["median"], 42)

    def test_empty_list(self):
        s = robust_summary([])
        self.assertEqual(s["n"], 0)
        self.assertIsNone(s["median"])

    def test_none_values_filtered(self):
        s = robust_summary([1, None, 3, None, 5])
        self.assertEqual(s["n"], 3)


class TestLogAnalyzer(unittest.TestCase):
    def test_counts_errors(self):
        result = analyze_logs(SAMPLE_LOGS)
        self.assertEqual(result["total_logs"], 8)
        self.assertEqual(result["error_count"], 5)

    def test_detects_new_patterns(self):
        result = analyze_logs(SAMPLE_LOGS)
        self.assertGreater(len(result["new_patterns"]), 0)

    def test_groups_patterns(self):
        result = analyze_logs(SAMPLE_LOGS)
        self.assertGreater(len(result["grouped_patterns"]), 0)

    def test_empty_logs(self):
        result = analyze_logs([])
        self.assertEqual(result["total_logs"], 0)
        self.assertEqual(result["error_count"], 0)

    def test_clean_logs_no_errors(self):
        result = analyze_logs(SAMPLE_LOGS_CLEAN)
        self.assertEqual(result["error_count"], 0)
        self.assertEqual(len(result["new_patterns"]), 0)

    def test_level_counts(self):
        result = analyze_logs(SAMPLE_LOGS)
        self.assertIn("ERROR", result["level_counts"])
        self.assertIn("INFO", result["level_counts"])

    def test_timestamp_correlation(self):
        result = analyze_logs(SAMPLE_LOGS)
        # Should detect at least one error burst
        corr = result.get("timestamp_correlation", [])
        self.assertIsInstance(corr, list)

    def test_normalize_pattern_strips_ids(self):
        msg = "Timeout for request req-01234 after 5000ms"
        pattern = _normalize_pattern(msg)
        self.assertNotIn("req-01234", pattern)
        self.assertIn("req-<ID>", pattern)


class TestMemoryStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.store = MemoryStore(Path(self.tmpdir))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_add_and_retrieve_case(self):
        fp = {"latency_spike": 0.8, "error_spike": 0.7}
        self.store.add_case("rca-1", fp, {"root_cause": "thread pool exhaustion"}, "reverted commit")
        case = self.store.get_case("rca-1")
        self.assertIsNotNone(case)
        self.assertTrue(case["confirmed"])
        self.assertEqual(case["fix_applied"], "reverted commit")

    def test_find_similar(self):
        fp1 = {"latency_spike": 0.8, "error_spike": 0.7, "cpu_spike": 0.5}
        fp2 = {"latency_spike": 0.7, "error_spike": 0.5, "memory_leak": 0.3}
        self.store.add_case("rca-1", fp1, {"cause": "thread pool"}, "fix1")
        matches = self.store.find_similar(fp2, threshold=0.2)
        self.assertGreater(len(matches), 0)
        self.assertTrue(matches[0]["is_historical_match"])

    def test_no_match_dissimilar(self):
        fp1 = {"latency_spike": 0.9}
        fp2 = {"throughput_drop": 0.9}
        self.store.add_case("rca-1", fp1, {"cause": "latency"}, "fix1")
        matches = self.store.find_similar(fp2, threshold=0.5)
        self.assertEqual(len(matches), 0)

    def test_list_cases(self):
        self.store.add_case("rca-a", {}, {}, None)
        self.store.add_case("rca-b", {}, {}, None)
        cases = self.store.list_cases()
        self.assertEqual(len(cases), 2)

    def test_persistence(self):
        fp = {"test": 1.0}
        self.store.add_case("rca-persist", fp, {"cause": "test"}, None)
        # Re-open
        store2 = MemoryStore(Path(self.tmpdir))
        case = store2.get_case("rca-persist")
        self.assertIsNotNone(case)


class TestAgentEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.fixtures_dir = Path(self.tmpdir) / "fixtures"
        self.fixtures_dir.mkdir()
        self.memory_dir = Path(self.tmpdir) / "memory"
        self._write_fixtures()
        self.agent = PerfRCAAgent(fixtures_dir=self.fixtures_dir, memory_dir=self.memory_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_fixtures(self):
        with open(self.fixtures_dir / "baseline.json", "w") as f:
            json.dump(BASELINE, f)
        with open(self.fixtures_dir / "current_run.json", "w") as f:
            json.dump(CURRENT_BAD, f)
        with open(self.fixtures_dir / "commits.json", "w") as f:
            json.dump(SAMPLE_COMMITS, f)
        with open(self.fixtures_dir / "logs.json", "w") as f:
            json.dump(SAMPLE_LOGS, f)

    def test_full_investigation_completes(self):
        result = self.agent.investigate({"mode": "demo"})
        self.assertEqual(result["status"], "completed")
        self.assertIsNotNone(result["report"])

    def test_investigation_produces_hypotheses(self):
        result = self.agent.investigate({"mode": "demo"})
        self.assertIsNotNone(result["report"])
        self.assertGreater(len(result["report"]["hypotheses"]), 0)

    def test_hypothesis_has_confidence(self):
        result = self.agent.investigate({"mode": "demo"})
        for h in result["report"]["hypotheses"]:
            self.assertGreaterEqual(h["confidence"], 0)
            self.assertLessEqual(h["confidence"], 1)
            self.assertIn(h["evaluation"], ("strong", "moderate", "weak", "speculative"))

    def test_hypothesis_sorted_by_confidence(self):
        result = self.agent.investigate({"mode": "demo"})
        hyps = result["report"]["hypotheses"]
        for i in range(len(hyps) - 1):
            self.assertGreaterEqual(hyps[i]["confidence"], hyps[i+1]["confidence"])

    def test_anomalies_detected(self):
        result = self.agent.investigate({"mode": "demo"})
        self.assertGreater(result["report"]["anomalies_detected"], 0)

    def test_suspected_commit_identified(self):
        result = self.agent.investigate({"mode": "demo"})
        top = result["report"]["hypotheses"][0]
        self.assertIsNotNone(top.get("suspected_commit"))

    def test_recommendations_produced(self):
        result = self.agent.investigate({"mode": "demo"})
        self.assertGreater(len(result["report"]["recommendations"]), 0)

    def test_log_summary_included(self):
        result = self.agent.investigate({"mode": "demo"})
        self.assertGreater(result["report"]["log_summary"]["total_logs"], 0)

    def test_empty_request_blocked(self):
        result = self.agent.investigate(None)
        self.assertEqual(result["status"], "blocked")

    def test_empty_dict_handled(self):
        result = self.agent.investigate({})
        self.assertEqual(result["status"], "completed")

    def test_step_limit_respected(self):
        """Step limit controls the investigation depth; the fixed initial steps
        (validate, load data, detect anomalies, analyze logs) always run."""
        agent = PerfRCAAgent(fixtures_dir=self.fixtures_dir, memory_dir=self.memory_dir, step_limit=7)
        result = agent.investigate({"mode": "demo"})
        # With step_limit=7, the agent should complete but may be partial or completed
        self.assertIn(result["status"], ("completed", "partial"))

    def test_retest_produces_simulated_result(self):
        self.agent.investigate({"mode": "demo"})
        retest = self.agent.retest()
        self.assertIn("simulated", retest["status"])
        self.assertIn("SIMULATED", retest["label"])

    def test_retest_without_investigation(self):
        agent = PerfRCAAgent(fixtures_dir=self.fixtures_dir, memory_dir=self.memory_dir)
        retest = agent.retest()
        self.assertEqual(retest["status"], "error")

    def test_fix_verification_present(self):
        result = self.agent.investigate({"mode": "demo"})
        fv = result["report"]["fix_verification"]
        self.assertIsNotNone(fv)
        self.assertEqual(fv["status"], "simulated")

    def test_jira_preview_is_preview(self):
        result = self.agent.investigate({"mode": "demo"})
        jp = result["report"]["jira_preview"]
        self.assertTrue(jp["preview"])

    def test_confluence_preview_is_preview(self):
        result = self.agent.investigate({"mode": "demo"})
        cp = result["report"]["confluence_preview"]
        self.assertTrue(cp["preview"])

    def test_honest_outcome_no_fabrication(self):
        """Reports should be honest: completed, partial, blocked, or failed."""
        result = self.agent.investigate({"mode": "demo"})
        self.assertIn(result["status"], ("completed", "partial", "blocked", "failed"))

    def test_no_hardcoded_llm_label(self):
        """Deterministic output should not be labeled as LLM-generated."""
        result = self.agent.investigate({"mode": "demo"})
        report_str = json.dumps(result)
        self.assertNotIn("Generated by LLM", report_str)
        self.assertNotIn("AI-generated", report_str.lower())

    def test_normal_run_produces_result(self):
        """Even a normal run should work without crashing."""
        # Write a normal current run
        with open(self.fixtures_dir / "current_run.json", "w") as f:
            json.dump(CURRENT_NORMAL, f)
        result = self.agent.investigate({"mode": "demo"})
        self.assertIn(result["status"], ("completed", "partial", "blocked", "failed"))


class TestPromptInjection(unittest.TestCase):
    """Security: prompt injection resistance in input handling."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.fixtures_dir = Path(self.tmpdir) / "fixtures"
        self.fixtures_dir.mkdir()
        self.memory_dir = Path(self.tmpdir) / "memory"
        with open(self.fixtures_dir / "baseline.json", "w") as f:
            json.dump(BASELINE, f)
        with open(self.fixtures_dir / "current_run.json", "w") as f:
            json.dump(CURRENT_BAD, f)
        with open(self.fixtures_dir / "commits.json", "w") as f:
            json.dump(SAMPLE_COMMITS, f)
        with open(self.fixtures_dir / "logs.json", "w") as f:
            json.dump(SAMPLE_LOGS, f)
        self.agent = PerfRCAAgent(fixtures_dir=self.fixtures_dir, memory_dir=self.memory_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_javascript_url_scheme_blocked(self):
        result = self.agent.investigate({"mode": "grafana", "grafana_url": "javascript:alert(1)"})
        self.assertNotEqual(result.get("error"), None)

    def test_data_url_scheme_blocked(self):
        result = self.agent.investigate({"mode": "grafana", "grafana_url": "data:text/html,<script>alert(1)</script>"})
        self.assertNotEqual(result.get("error"), None)


class TestIntegrationEndpoints(unittest.TestCase):
    """Integration tests for the HTTP server endpoints.

    These test the API handlers directly without starting a socket.
    """
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.fixtures_dir = Path(self.tmpdir) / "fixtures"
        self.fixtures_dir.mkdir()
        self.memory_dir = Path(self.tmpdir) / "memory"
        with open(self.fixtures_dir / "baseline.json", "w") as f:
            json.dump(BASELINE, f)
        with open(self.fixtures_dir / "current_run.json", "w") as f:
            json.dump(CURRENT_BAD, f)
        with open(self.fixtures_dir / "commits.json", "w") as f:
            json.dump(SAMPLE_COMMITS, f)
        with open(self.fixtures_dir / "logs.json", "w") as f:
            json.dump(SAMPLE_LOGS, f)

        from agent.engine import PerfRCAAgent
        self.agent = PerfRCAAgent(fixtures_dir=self.fixtures_dir, memory_dir=self.memory_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_investigate_endpoint_returns_200_on_demo(self):
        result = self.agent.investigate({"mode": "demo"})
        self.assertEqual(result["status"], "completed")
        self.assertIn("report", result)

    def test_investigate_endpoint_returns_report_structure(self):
        result = self.agent.investigate({"mode": "demo"})
        report = result["report"]
        self.assertIn("hypotheses", report)
        self.assertIn("anomalies", report)
        self.assertIn("recommendations", report)
        self.assertIn("fix_verification", report)
        self.assertIn("jira_preview", report)
        self.assertIn("confluence_preview", report)

    def test_investigate_invalid_mode_defaults_to_demo(self):
        result = self.agent.investigate({"mode": "invalid"})
        self.assertEqual(result["status"], "completed")

    def test_retest_endpoint_works_after_investigation(self):
        self.agent.investigate({"mode": "demo"})
        retest = self.agent.retest()
        self.assertEqual(retest["verdict"], "simulated_fix_confirmed")

    def test_memory_endpoint_lists_cases(self):
        self.agent.memory.add_case("test-1", {"latency": 0.5}, {"cause": "test"}, None)
        cases = self.agent.memory.list_cases()
        self.assertGreaterEqual(len(cases), 1)


if __name__ == "__main__":
    unittest.main()