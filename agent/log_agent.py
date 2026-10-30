"""LogAgent — Specialized AI agent for log intelligence, pattern grouping, and burst detection.

Responsibilities:
- Normalizes raw log lines by masking dynamic tokens (UUIDs, hashes, request IDs, numbers)
- Groups logs by normalized pattern signatures
- Detects sudden error bursts within narrow time windows (micro-bursts)
- Extracts new or spiking error patterns unique to regression periods
"""

from typing import Dict, List, Any, Optional
from .log_analyzer import analyze_logs, _normalize_pattern


class LogAgent:
    """Specialized agent analyzing application logs, exception traces, and error bursts."""

    NAME = "LogAgent"
    ROLE = "Log Pattern & Error Burst Specialist"

    def __init__(self, burst_window_seconds: int = 10, min_pattern_count: int = 3):
        self.burst_window_seconds = burst_window_seconds
        self.min_pattern_count = min_pattern_count

    def analyze(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform deep log pattern mining and error burst detection."""
        analysis = analyze_logs(logs)

        # Classify dominant error patterns
        dominant_errors = []
        for p in analysis.get("new_patterns", []):
            dominant_errors.append({
                "pattern": p.get("pattern"),
                "frequency": p.get("count"),
                "first_seen": p.get("first_seen"),
                "last_seen": p.get("last_seen"),
                "is_connection_related": any(k in p.get("pattern", "").lower() for k in ("connection", "pool", "timeout")),
                "is_thread_related": any(k in p.get("pattern", "").lower() for k in ("thread", "worker", "exhausted", "reject")),
                "is_database_related": any(k in p.get("pattern", "").lower() for k in ("deadlock", "lock", "select for update", "sql"))
            })

        bursts = analysis.get("timestamp_correlation", [])
        total_errors = analysis.get("error_count", 0)
        total_logs = analysis.get("total_logs", 0)

        error_rate_pct = round((total_errors / total_logs * 100), 2) if total_logs > 0 else 0.0

        return {
            "agent": self.NAME,
            "role": self.ROLE,
            "status": "completed",
            "total_logs_analyzed": total_logs,
            "error_count": total_errors,
            "error_rate_pct": error_rate_pct,
            "new_patterns_count": len(dominant_errors),
            "dominant_error_patterns": dominant_errors,
            "error_bursts_detected": len(bursts),
            "error_bursts": bursts,
            "has_pool_exhaustion": any(e["is_thread_related"] or e["is_connection_related"] for e in dominant_errors),
            "has_database_contention": any(e["is_database_related"] for e in dominant_errors),
            "level_distribution": analysis.get("level_counts", {})
        }
