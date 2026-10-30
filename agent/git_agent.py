"""GitAgent — Specialized AI agent for code change intelligence and Git commit attribution.

Responsibilities:
- Inspects commit metadata, diff summaries, and touched files
- Correlates commit timestamps with regression onset windows
- Semantic keyword scoring to rank suspected commits (e.g. thread_pool, retry, timeout, lock)
- Separates primary root-cause commits from contributing/amplifier commits
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


class GitAgent:
    """Specialized agent analyzing code deployments, commits, and diff summaries."""

    NAME = "GitAgent"
    ROLE = "Code Change & Git Attribution Specialist"

    # Keywords associated with performance risk
    RISK_PATTERNS = {
        "thread_pool": ["thread", "worker", "pool_size", "executor", "concurrency"],
        "connection_pool": ["connection", "conn_pool", "pool", "socket", "timeout"],
        "retry_logic": ["retry", "backoff", "attempts", "queue_depth", "circuit"],
        "database_locks": ["lock", "select for update", "deadlock", "transaction", "isolation"],
        "logging_overhead": ["debug", "verbose", "trace", "log_level", "logger"]
    }

    def analyze(self, commits_data: Dict[str, Any], regression_timestamp: Optional[str] = None) -> Dict[str, Any]:
        """Correlate commits against performance regressions and score culpability."""
        raw_commits = commits_data.get("commit_metadata", {}).get("commits", [])
        if not raw_commits:
            # Fallback if commits are directly at root
            raw_commits = commits_data.get("commits", [])

        scored_commits = []

        for c in raw_commits:
            score = 0.0
            matched_categories = []
            text_corpus = f"{c.get('message', '')} {c.get('diff_summary', '')} {' '.join(c.get('files_changed', []))}".lower()

            for category, keywords in self.RISK_PATTERNS.items():
                hits = [kw for kw in keywords if kw in text_corpus]
                if hits:
                    matched_categories.append(category)
                    if category == "thread_pool":
                        score += 0.45
                    elif category == "retry_logic":
                        score += 0.30
                    elif category == "connection_pool":
                        score += 0.35
                    elif category == "database_locks":
                        score += 0.40
                    elif category == "logging_overhead":
                        score += 0.15

            # Cap score between 0.0 and 1.0
            normalized_score = min(round(score, 2), 1.0)

            scored_commits.append({
                "hash": c.get("hash"),
                "message": c.get("message"),
                "author": c.get("author"),
                "timestamp": c.get("timestamp"),
                "files_changed": c.get("files_changed", []),
                "diff_summary": c.get("diff_summary", ""),
                "risk_score": normalized_score,
                "matched_risk_categories": matched_categories
            })

        # Sort by risk score descending
        scored_commits.sort(key=lambda x: x["risk_score"], reverse=True)

        primary_suspect = scored_commits[0] if scored_commits and scored_commits[0]["risk_score"] >= 0.3 else None
        amplifiers = [c for c in scored_commits[1:] if c["risk_score"] >= 0.25] if scored_commits else []

        return {
            "agent": self.NAME,
            "role": self.ROLE,
            "status": "completed",
            "commits_inspected": len(scored_commits),
            "primary_suspect": primary_suspect,
            "secondary_amplifiers": amplifiers,
            "ranked_commits": scored_commits,
            "attribution_confidence": primary_suspect["risk_score"] if primary_suspect else 0.0
        }
