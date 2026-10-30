"""Tests for the Multi-Agent Swarm (MetricsAgent, LogAgent, GitAgent, RemediationAgent)."""

import unittest
from pathlib import Path

from agent.metrics_agent import MetricsAgent
from agent.log_agent import LogAgent
from agent.git_agent import GitAgent
from agent.remediation_agent import RemediationAgent
from agent.engine import PerfRCAAgent

BASELINE = {
    "run_id": "base-1",
    "service": "auth-service",
    "metrics": {
        "latency": {"p50_ms": 10, "p95_ms": 50, "p99_ms": 100},
        "throughput": {"requests_per_second": 1000},
        "error_rate": {"percentage": 0.5, "total_errors": 50},
        "resources": {"cpu_percent": 30, "memory_gb": 1.0}
    }
}

CURRENT_BAD = {
    "run_id": "bad-1",
    "service": "auth-service",
    "metrics": {
        "latency": {"p50_ms": 30, "p95_ms": 200, "p99_ms": 450},
        "throughput": {"requests_per_second": 500},
        "error_rate": {"percentage": 5.0, "total_errors": 500},
        "resources": {"cpu_percent": 90, "memory_gb": 3.5}
    }
}

CURRENT_GOOD = {
    "run_id": "good-1",
    "service": "auth-service",
    "metrics": {
        "latency": {"p50_ms": 10, "p95_ms": 51, "p99_ms": 102},
        "throughput": {"requests_per_second": 990},
        "error_rate": {"percentage": 0.51, "total_errors": 51},
        "resources": {"cpu_percent": 31, "memory_gb": 1.02}
    }
}

SAMPLE_LOGS = [
    {"timestamp": "2026-10-27T09:14:58Z", "level": "ERROR", "message": "Timeout acquiring connection from pool after 5000ms for request req-0100"},
    {"timestamp": "2026-10-27T09:14:58Z", "level": "ERROR", "message": "Timeout acquiring connection from pool after 5000ms for request req-0101"},
    {"timestamp": "2026-10-27T09:14:59Z", "level": "ERROR", "message": "Timeout acquiring connection from pool after 5000ms for request req-0102"},
    {"timestamp": "2026-10-27T09:15:00Z", "level": "ERROR", "message": "Thread pool exhausted, rejecting request req-0200"},
    {"timestamp": "2026-10-27T09:15:00Z", "level": "ERROR", "message": "Thread pool exhausted, rejecting request req-0201"},
    {"timestamp": "2026-10-27T09:15:00Z", "level": "ERROR", "message": "Thread pool exhausted, rejecting request req-0202"},
    {"timestamp": "2026-10-27T09:15:05Z", "level": "INFO", "message": "Auth token validated for req-0300"}
]

SAMPLE_COMMITS = {
    "commit_metadata": {
        "commits": [
            {"hash": "a1b2c3d", "message": "Reduce thread pool size 32->24", "diff_summary": "thread_pool_size 24", "files_changed": ["pool.py"]},
            {"hash": "e4f5g6h", "message": "Add connection retry with hard timeout", "diff_summary": "retry with deep queue 200", "files_changed": ["retry.py"]},
            {"hash": "z9y8x7w", "message": "Update docs and readme", "diff_summary": "docs update", "files_changed": ["README.md"]}
        ]
    }
}


class TestMetricsAgent(unittest.TestCase):
    def setUp(self):
        self.agent = MetricsAgent()

    def test_detects_regressions(self):
        res = self.agent.analyze(BASELINE, CURRENT_BAD)
        self.assertEqual(res["agent"], "MetricsAgent")
        self.assertEqual(res["status"], "completed")
        self.assertTrue(res["latency_regressed"])
        self.assertTrue(res["error_spiking"])
        self.assertGreater(res["critical_count"], 0)

    def test_clean_run_no_anomalies(self):
        res = self.agent.analyze(BASELINE, CURRENT_GOOD)
        self.assertEqual(res["anomalies_detected"], 0)
        self.assertFalse(res["latency_regressed"])

    def test_bottleneck_classification(self):
        res = self.agent.analyze(BASELINE, CURRENT_BAD)
        self.assertIn(res["primary_bottleneck"], ("error_spike", "latency_saturation", "resource_exhaustion"))


class TestLogAgent(unittest.TestCase):
    def setUp(self):
        self.agent = LogAgent()

    def test_analyzes_error_bursts(self):
        res = self.agent.analyze(SAMPLE_LOGS)
        self.assertEqual(res["agent"], "LogAgent")
        self.assertEqual(res["total_logs_analyzed"], 7)
        self.assertEqual(res["error_count"], 6)
        self.assertTrue(res["has_pool_exhaustion"])
        self.assertGreater(res["new_patterns_count"], 0)

    def test_handles_clean_logs(self):
        clean_logs = [{"timestamp": "2026-10-27T09:00:00Z", "level": "INFO", "message": "Warmup completed"}]
        res = self.agent.analyze(clean_logs)
        self.assertEqual(res["error_count"], 0)
        self.assertFalse(res["has_pool_exhaustion"])


class TestGitAgent(unittest.TestCase):
    def setUp(self):
        self.agent = GitAgent()

    def test_identifies_primary_suspect(self):
        res = self.agent.analyze(SAMPLE_COMMITS)
        self.assertEqual(res["agent"], "GitAgent")
        self.assertEqual(res["commits_inspected"], 3)
        suspect = res["primary_suspect"]
        self.assertIsNotNone(suspect)
        self.assertEqual(suspect["hash"], "a1b2c3d")
        self.assertIn("thread_pool", suspect["matched_risk_categories"])

    def test_identifies_secondary_amplifiers(self):
        res = self.agent.analyze(SAMPLE_COMMITS)
        amplifiers = res["secondary_amplifiers"]
        self.assertTrue(any(a["hash"] == "e4f5g6h" for a in amplifiers))

    def test_handles_empty_commits(self):
        res = self.agent.analyze({"commit_metadata": {"commits": []}})
        self.assertEqual(res["commits_inspected"], 0)
        self.assertIsNone(res["primary_suspect"])


class TestRemediationAgent(unittest.TestCase):
    def setUp(self):
        self.agent = RemediationAgent()

    def test_formulates_recommendations(self):
        recs = self.agent.formulate_recommendations({}, CURRENT_BAD, BASELINE)
        self.assertGreater(len(recs), 0)
        categories = [r["category"] for r in recs]
        self.assertIn("capacity_planning", categories)
        self.assertIn("connection_tuning", categories)
        self.assertIn("exception_handling", categories)

    def test_builds_simulation(self):
        sim = self.agent.build_verification_simulation(BASELINE, {"title": "Thread pool fix"})
        self.assertEqual(sim["status"], "simulated")
        self.assertIn("estimated_metrics_after_fix", sim)
        self.assertLess(sim["estimated_metrics_after_fix"]["latency_p99_ms"], 300)

    def test_previews_generated(self):
        jira = self.agent.generate_jira_preview("auth-service", {"title": "Thread Pool Exhaustion", "suspected_commit": "a1b2c3d"})
        self.assertTrue(jira["preview"])
        self.assertIn("a1b2c3d", jira["description"])

        conf = self.agent.generate_confluence_preview("auth-service", "base-1", "bad-1", {"title": "Thread Pool Exhaustion", "confidence": 0.88})
        self.assertTrue(conf["preview"])
        self.assertEqual(len(conf["sections"]), 3)


class TestMultiAgentOrchestration(unittest.TestCase):
    def test_orchestrator_coordinates_swarm(self):
        agent = PerfRCAAgent()
        self.assertIsInstance(agent.metrics_agent, MetricsAgent)
        self.assertIsInstance(agent.log_agent, LogAgent)
        self.assertIsInstance(agent.git_agent, GitAgent)
        self.assertIsInstance(agent.remediation_agent, RemediationAgent)

        res = agent.investigate({"mode": "demo"})
        self.assertEqual(res["status"], "completed")
        report = res["report"]
        self.assertIn("multi_agent_swarm", report)
        swarm = report["multi_agent_swarm"]
        self.assertEqual(swarm["orchestrator"]["status"], "completed")
        self.assertEqual(swarm["metrics_agent"]["agent"], "MetricsAgent")
        self.assertEqual(swarm["log_agent"]["agent"], "LogAgent")
        self.assertEqual(swarm["git_agent"]["agent"], "GitAgent")
        self.assertEqual(swarm["remediation_agent"]["name"], "RemediationAgent")


if __name__ == "__main__":
    unittest.main()
