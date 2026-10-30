"""MetricsAgent — Specialized AI agent for time-series and metric telemetry analysis.

Responsibilities:
- Baseline vs current run statistical comparison
- Anomaly detection with severity classification (low, medium, high, critical)
- Resource saturation analysis (CPU, memory, connection pool, buffer pool)
- Metric bottleneck attribution
"""

from typing import Dict, List, Any, Optional
from .anomaly import compare_baseline, describe_anomalies, robust_summary


class MetricsAgent:
    """Specialized agent analyzing performance metrics and system saturation."""

    NAME = "MetricsAgent"
    ROLE = "Telemetry & Resource Saturation Specialist"

    def __init__(self, anomaly_threshold_pct: float = 10.0):
        self.anomaly_threshold_pct = anomaly_threshold_pct

    def analyze(self, baseline: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
        """Perform deep telemetry inspection comparing baseline and current runs."""
        anomalies = compare_baseline(baseline, current, threshold_pct=self.anomaly_threshold_pct)
        summary_desc = describe_anomalies(anomalies)

        # Categorize anomalies
        latency_anomalies = [a for a in anomalies if "latency" in a.get("metric", "")]
        error_anomalies = [a for a in anomalies if "error" in a.get("metric", "")]
        resource_anomalies = [a for a in anomalies if any(k in a.get("metric", "") for k in ("cpu", "memory", "disk", "network"))]
        throughput_anomalies = [a for a in anomalies if "throughput" in a.get("metric", "")]

        # Determine primary bottleneck
        primary_bottleneck = None
        if error_anomalies and any(a.get("severity") in ("critical", "high") for a in error_anomalies):
            primary_bottleneck = "error_spike"
        elif latency_anomalies and any(a.get("severity") in ("critical", "high") for a in latency_anomalies):
            primary_bottleneck = "latency_saturation"
        elif resource_anomalies and any(a.get("severity") in ("critical", "high") for a in resource_anomalies):
            primary_bottleneck = "resource_exhaustion"

        critical_count = sum(1 for a in anomalies if a.get("severity") == "critical")
        high_count = sum(1 for a in anomalies if a.get("severity") == "high")

        return {
            "agent": self.NAME,
            "role": self.ROLE,
            "status": "completed",
            "anomalies_detected": len(anomalies),
            "critical_count": critical_count,
            "high_count": high_count,
            "anomalies": anomalies,
            "primary_bottleneck": primary_bottleneck,
            "summary": summary_desc,
            "latency_regressed": len(latency_anomalies) > 0,
            "error_spiking": len(error_anomalies) > 0,
            "resource_pressured": len(resource_anomalies) > 0,
            "throughput_dropped": len(throughput_anomalies) > 0
        }
