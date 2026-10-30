"""Benchmark Evaluation Suite for perfRCA Autonomous Incident Investigation.

Evaluates known incident failure modes:
1. Thread pool exhaustion and connection cascade (Auth Service)
2. Database lock contention and deadlocks under batch workload (Payment DB)
3. Healthy run verification (No false positive alarms or accusations)
4. Inconclusive run verification (Uncertainty reflected honestly)
5. Log error micro-burst and commit diff attribution
"""

import unittest
from agent.engine import PerfRCAAgent, AgentState
from agent.log_agent import LogAgent
from agent.git_agent import GitAgent
from agent.anomaly import compare_baseline


class TestBenchmarkEvaluation(unittest.TestCase):
    """Rigorous benchmark evaluation covering multiple failure modes."""

    def setUp(self):
        self.agent = PerfRCAAgent()
        self.log_agent = LogAgent()
        self.git_agent = GitAgent()

    def test_benchmark_thread_pool_exhaustion_incident(self):
        """Benchmark 1: Auth service thread pool exhaustion (commit a1b2c3d)."""
        result = self.agent.investigate({"mode": "demo"})
        self.assertEqual(result["status"], AgentState.COMPLETED)
        report = result["report"]
        self.assertIsNotNone(report)

        # 1. Anomaly detection accuracy
        anomalies = report["anomalies"]
        self.assertGreater(len(anomalies), 0)
        p99_anom = next((a for a in anomalies if a["metric"] == "latency_p99_ms"), None)
        self.assertIsNotNone(p99_anom)
        self.assertIn(p99_anom["severity"], ("high", "critical"))

        # 2. Hypothesis ranking & confidence
        hyps = report["hypotheses"]
        self.assertGreater(len(hyps), 0)
        top_hypo = hyps[0]
        self.assertEqual(top_hypo["id"], "H_CONN_POOL")
        self.assertGreaterEqual(top_hypo["confidence"], 0.80)
        self.assertEqual(top_hypo["evaluation"], "strong")

        # 3. Commit attribution
        self.assertEqual(top_hypo["suspected_commit"], "a1b2c3d")
        self.assertIn("e4f5g6h", top_hypo.get("secondary_commits", []))

        # 4. Multi-agent swarm verification
        swarm = report.get("multi_agent_swarm", {})
        self.assertIn("metrics_agent", swarm)
        self.assertIn("log_agent", swarm)
        self.assertIn("git_agent", swarm)
        self.assertIn("remediation_agent", swarm)
        self.assertEqual(swarm["git_agent"]["primary_suspect"]["hash"], "a1b2c3d")

        # 5. Distributed trace correlation
        self.assertIn("correlated_traces", top_hypo)
        self.assertIn("abc123def456", top_hypo["correlated_traces"])

    def test_benchmark_database_lock_contention_incident(self):
        """Benchmark 2: Payment DB lock contention and deadlocks from batch queries."""
        result = self.agent.investigate({"mode": "demo", "scenario": "db"})
        self.assertEqual(result["status"], AgentState.COMPLETED)
        report = result["report"]
        self.assertIsNotNone(report)

        # 1. Correct scenario service identification
        self.assertEqual(report["service"], "payment-db")

        # 2. Top hypothesis is DB lock contention
        hyps = report["hypotheses"]
        top_hypo = hyps[0]
        self.assertEqual(top_hypo["id"], "H_DB_LOCK_CONTENTION")
        self.assertGreaterEqual(top_hypo["confidence"], 0.85)

        # 3. Supporting evidence captures lock contention, deadlocks, and slow query
        evidence_text = " ".join(top_hypo["supporting_evidence"]).lower()
        self.assertIn("row lock contention", evidence_text)
        self.assertIn("deadlock", evidence_text)
        self.assertIn("select for update", evidence_text)

        # 4. Actionable prescriptive recommendations
        recs = top_hypo["fix_recommendation"]
        self.assertIn("throttle", recs.lower())
        self.assertIn("skip locked", recs.lower())

    def test_benchmark_healthy_run_no_false_positives(self):
        """Benchmark 3: Healthy baseline vs baseline run produces no false alarms."""
        baseline, _ = self.agent._load_data({"scenario": "demo"})
        # Compare baseline against itself
        anomalies = compare_baseline(baseline, baseline)
        self.assertEqual(len(anomalies), 0)

        # Investigating a run with identical metrics
        original_load = self.agent._load_data
        self.agent._load_data = lambda req: (baseline, baseline)
        try:
            result = self.agent.investigate({"mode": "demo"})
            self.assertEqual(result["status"], AgentState.COMPLETED)
            self.assertTrue(any("within normal bounds" in obs for obs in result["observations"]))
            self.assertIsNone(result["report"])
        finally:
            self.agent._load_data = original_load

    def test_benchmark_inconclusive_run_uncertainty(self):
        """Benchmark 4: Minimal metric deviations yield honest lower confidence."""
        baseline, current = self.agent._load_data({"scenario": "demo"})
        # Create a minor deviation run (only 12% increase, below major anomaly thresholds)
        mild_current = dict(current)
        mild_current["metrics"] = {
            "latency": {"p99_ms": int(baseline["metrics"]["latency"]["p99_ms"] * 1.12),
                        "p50_ms": baseline["metrics"]["latency"]["p50_ms"],
                        "p95_ms": baseline["metrics"]["latency"]["p95_ms"]},
            "throughput": baseline["metrics"]["throughput"],
            "error_rate": baseline["metrics"]["error_rate"],
            "resources": baseline["metrics"]["resources"]
        }

        original_load = self.agent._load_data
        self.agent._load_data = lambda req: (baseline, mild_current)
        try:
            result = self.agent.investigate({"mode": "demo"})
            self.assertEqual(result["status"], AgentState.COMPLETED)
            if result.get("report"):
                top_hypo = result["report"]["hypotheses"][0]
                # Confidence should not be artificially inflated to >80% without solid evidence
                self.assertLess(top_hypo["confidence"], 0.70)
        finally:
            self.agent._load_data = original_load

    def test_benchmark_log_micro_burst_detection(self):
        """Benchmark 5: LogAgent detects sub-10-second error bursts."""
        logs = [
            {"timestamp": "2026-10-27T09:15:01Z", "level": "ERROR", "message": "Connection timeout"},
            {"timestamp": "2026-10-27T09:15:02Z", "level": "ERROR", "message": "Connection timeout"},
            {"timestamp": "2026-10-27T09:15:03Z", "level": "ERROR", "message": "Connection timeout"},
            {"timestamp": "2026-10-27T09:15:04Z", "level": "ERROR", "message": "Thread exhausted"},
            {"timestamp": "2026-10-27T09:15:05Z", "level": "ERROR", "message": "Thread exhausted"},
            {"timestamp": "2026-10-27T09:15:06Z", "level": "ERROR", "message": "Thread exhausted"},
        ]
        findings = self.log_agent.analyze(logs)
        self.assertEqual(findings["error_count"], 6)
        bursts = findings.get("error_bursts", [])
        self.assertGreater(len(bursts), 0)
        self.assertEqual(bursts[0]["error_count"], 6)

    def test_benchmark_git_diff_attribution_scoring(self):
        """Benchmark 6: GitAgent attributes correct suspected commit."""
        commits = self.agent._load_commits()
        findings = self.git_agent.analyze(commits)
        self.assertEqual(findings["primary_suspect"]["hash"], "a1b2c3d")
        self.assertGreaterEqual(findings["primary_suspect"]["risk_score"], 0.7)
        self.assertIn("e4f5g6h", [a["hash"] for a in findings.get("secondary_amplifiers", [])])


if __name__ == "__main__":
    unittest.main()
