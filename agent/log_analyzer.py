"""Log analysis — pattern grouping, frequency counting, error-spike detection."""

import re
from collections import Counter
from datetime import datetime, timezone


def analyze_logs(log_entries):
    """Analyze a list of timestamped log entries.

    Args:
        log_entries: list of dicts with 'timestamp', 'level', 'message' keys.

    Returns:
        dict with total_logs, error_count, grouped_patterns, new_patterns,
        timestamp_correlation, and level_counts.
    """
    if not log_entries:
        return {
            "total_logs": 0,
            "error_count": 0,
            "grouped_patterns": [],
            "new_patterns": [],
            "timestamp_correlation": [],
            "level_counts": {}
        }

    total = len(log_entries)
    errors = [e for e in log_entries if e.get("level", "").upper() in ("ERROR", "CRITICAL")]
    error_count = len(errors)

    # Group log messages by pattern (strip variable parts like IDs)
    patterns = {}
    for entry in log_entries:
        pattern = _normalize_pattern(entry.get("message", ""))
        if pattern not in patterns:
            patterns[pattern] = {"pattern": pattern, "count": 0, "levels": set(), "first_seen": entry.get("timestamp"), "last_seen": entry.get("timestamp")}
        patterns[pattern]["count"] += 1
        patterns[pattern]["levels"].add(entry.get("level"))
        if entry.get("timestamp", "") < patterns[pattern]["first_seen"]:
            patterns[pattern]["first_seen"] = entry["timestamp"]
        if entry.get("timestamp", "") > patterns[pattern]["last_seen"]:
            patterns[pattern]["last_seen"] = entry["timestamp"]

    grouped = sorted(patterns.values(), key=lambda p: p["count"], reverse=True)
    for p in grouped:
        p["levels"] = sorted(p["levels"])

    # Identify error-only patterns as potential "new" or "spiking" issues
    new_patterns = [
        {"pattern": p["pattern"], "count": p["count"], "first_seen": p["first_seen"], "last_seen": p["last_seen"]}
        for p in grouped
        if "ERROR" in p.get("levels", []) and p["count"] >= 3
    ]

    # Level counts
    level_counts = dict(Counter(e.get("level", "UNKNOWN") for e in log_entries))

    # Simple timestamp correlation: look for error bursts
    timestamp_correlation = _correlate_timestamps(log_entries)

    return {
        "total_logs": total,
        "error_count": error_count,
        "grouped_patterns": grouped,
        "new_patterns": new_patterns,
        "timestamp_correlation": timestamp_correlation,
        "level_counts": level_counts
    }


def _normalize_pattern(message):
    """Normalize a log message into a pattern by replacing variable parts."""
    # Replace UUIDs, request IDs, hex hashes
    msg = re.sub(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', '<UUID>', message, flags=re.IGNORECASE)
    msg = re.sub(r'\b[0-9a-f]{32,}\b', '<HASH>', msg, flags=re.IGNORECASE)
    # Replace request IDs: req-xxxx
    msg = re.sub(r'req-\d{4,}', 'req-<ID>', msg)
    # Replace numbers (timestamps, durations, counts)
    msg = re.sub(r'\b\d+(?:\.\d+)?(?:ms|MB|GB|s|%)\b', '<NUM><UNIT>', msg)
    # Replace bare numbers that look like measurements
    msg = re.sub(r'(?<![a-zA-Z])\d+(?:\.\d+)?(?![a-zA-Z])', '<NUM>', msg)
    return msg.strip()


def _correlate_timestamps(log_entries):
    """Find bursts of errors within short time windows."""
    if not log_entries:
        return []

    errors_only = [
        e for e in log_entries
        if e.get("level", "").upper() in ("ERROR", "CRITICAL")
    ]

    if len(errors_only) < 3:
        return []

    bursts = []
    window_start = None
    window_count = 0
    window_entries = []

    for e in sorted(log_entries, key=lambda x: x.get("timestamp", "")):
        ts = e.get("timestamp", "")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        if window_start is None:
            window_start = dt
            window_count = 0
            window_entries = []

        if (dt - window_start).total_seconds() <= 10:
            if e.get("level", "").upper() in ("ERROR", "CRITICAL"):
                window_count += 1
                window_entries.append(e.get("message", ""))
        else:
            if window_count >= 3:
                bursts.append({
                    "start": window_start.isoformat() + "Z",
                    "error_count": window_count,
                    "sample_messages": list(set(window_entries))[:5]
                })
            window_start = dt
            window_count = 1 if e.get("level", "").upper() in ("ERROR", "CRITICAL") else 0
            window_entries = [e.get("message", "")] if window_count > 0 else []

    # Don't forget the last window
    if window_count >= 3:
        bursts.append({
            "start": window_start.isoformat() + "Z",
            "error_count": window_count,
            "sample_messages": list(set(window_entries))[:5]
        })

    return bursts