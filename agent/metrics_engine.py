"""Metrics engine — generates time-series data from fixtures and computes summaries."""

import csv
import io
import math
import random
from datetime import datetime, timezone, timedelta


def _now_utc():
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _jitter(value: float, pct: float = 0.05) -> float:
    """Add ±pct jitter to a value."""
    if value == 0:
        return 0.0
    noise = value * pct * (2 * random.random() - 1)
    return value + noise


# Metric definitions: (key_path_in_fixture, unit, display_name)
_METRIC_DEFS = {
    "latency_p99_ms": ("metrics.latency.p99_ms", "ms", "P99 Latency"),
    "latency_p95_ms": ("metrics.latency.p95_ms", "ms", "P95 Latency"),
    "latency_p50_ms": ("metrics.latency.p50_ms", "ms", "P50 Latency"),
    "latency_mean_ms": ("metrics.latency.mean_ms", "ms", "Mean Latency"),
    "throughput_rps": ("metrics.throughput.requests_per_second", "req/s", "Throughput"),
    "error_rate_pct": ("metrics.error_rate.percentage", "%", "Error Rate"),
    "cpu_percent": ("metrics.resources.cpu_percent", "%", "CPU Usage"),
    "memory_gb": ("metrics.resources.memory_gb", "GB", "Memory Usage"),
}

# Alias map for incoming metric keys
_METRIC_ALIASES = {
    "latency_p99_ms": "latency_p99_ms",
    "latency_p99": "latency_p99_ms",
    "p99_latency": "latency_p99_ms",
    "latency_p95_ms": "latency_p95_ms",
    "latency_p50_ms": "latency_p50_ms",
    "latency_mean_ms": "latency_mean_ms",
    "throughput": "throughput_rps",
    "throughput_rps": "throughput_rps",
    "requests_per_second": "throughput_rps",
    "error_rate": "error_rate_pct",
    "error_rate_pct": "error_rate_pct",
    "error_rate_percentage": "error_rate_pct",
    "cpu": "cpu_percent",
    "cpu_percent": "cpu_percent",
    "memory": "memory_gb",
    "memory_gb": "memory_gb",
}


def _get_nested(d: dict, path: str):
    """Get a value from a nested dict using dot notation."""
    parts = path.split(".")
    cur = d
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _resolve_metric_key(metric_key: str) -> str:
    """Resolve alias or return canonical key if already canonical."""
    return _METRIC_ALIASES.get(metric_key, metric_key)


def generate_time_series(baseline: dict, current: dict, metric_key: str,
                         n_points: int = 60) -> list:
    """Generate a synthetic but plausible time-series for a metric.

    First half of points trend from baseline value, second half show regression
    toward current value. Random seed is deterministic per metric_key for
    reproducibility.

    Args:
        baseline: Baseline fixture dict.
        current: Current run fixture dict.
        metric_key: Metric key (canonical or alias).
        n_points: Number of data points to generate.

    Returns:
        List of {"timestamp": ISO, "value": float, "is_baseline": bool}
    """
    canonical = _resolve_metric_key(metric_key)
    defn = _METRIC_DEFS.get(canonical)
    if defn is None:
        # Unknown metric — return empty
        return []

    path, unit, name = defn
    baseline_val = _get_nested(baseline, path)
    current_val = _get_nested(current, path)

    if baseline_val is None or current_val is None:
        return []

    baseline_val = float(baseline_val)
    current_val = float(current_val)

    # Deterministic random seed per metric
    rng = random.Random(hash(canonical) & 0xFFFFFFFF)

    now = _now_utc()
    # Generate points going back n_points minutes
    points = []
    half = n_points // 2

    for i in range(n_points):
        dt = now - timedelta(minutes=(n_points - 1 - i))
        is_baseline_point = i < half

        if is_baseline_point:
            # Trend from baseline
            progress = i / max(half - 1, 1)
            base = baseline_val * (1 + 0.02 * progress)  # slight drift
        else:
            # Transition toward current (regression)
            regression_progress = (i - half) / max(half - 1, 1)
            base = baseline_val + (current_val - baseline_val) * regression_progress

        # Add ±5% jitter
        noise = base * 0.05 * (2 * rng.random() - 1)
        value = max(0.0, base + noise)
        value = round(value, 3)

        points.append({
            "timestamp": _iso(dt),
            "value": value,
            "is_baseline": is_baseline_point,
        })

    return points


def get_metrics_summary(baseline: dict, current: dict) -> dict:
    """Return a structured summary of all key metrics with baseline/current values, % change, severity, and unit."""
    summary = {}
    for canonical, (path, unit, display_name) in _METRIC_DEFS.items():
        b_val = _get_nested(baseline, path)
        c_val = _get_nested(current, path)

        if b_val is None and c_val is None:
            continue

        b_val = float(b_val) if b_val is not None else None
        c_val = float(c_val) if c_val is not None else None

        # Compute % change
        if b_val is not None and c_val is not None and b_val != 0:
            pct_change = (c_val - b_val) / abs(b_val) * 100
        elif b_val == 0 and c_val is not None and c_val != 0:
            pct_change = float("inf")
        else:
            pct_change = 0.0

        # Determine severity based on % change magnitude
        abs_pct = abs(pct_change) if math.isfinite(pct_change) else 100.0
        if abs_pct > 100:
            severity = "critical"
        elif abs_pct > 50:
            severity = "high"
        elif abs_pct > 20:
            severity = "medium"
        elif abs_pct > 10:
            severity = "low"
        else:
            severity = "ok"

        summary[canonical] = {
            "display_name": display_name,
            "baseline": b_val,
            "current": c_val,
            "percent_change": round(pct_change, 2) if math.isfinite(pct_change) else None,
            "severity": severity,
            "unit": unit,
        }

    return summary


def get_anomaly_intervals(series: list, baseline_val: float,
                          threshold_pct: float = 20.0) -> list:
    """Return list of intervals where the metric deviated beyond threshold_pct from baseline_val.

    Args:
        series: List of time-series points {"timestamp": ISO, "value": float, ...}.
        baseline_val: The reference (baseline) value.
        threshold_pct: Percentage deviation threshold.

    Returns:
        List of {"start": ISO, "end": ISO, "max_deviation_pct": float}
    """
    if not series or baseline_val is None:
        return []

    baseline_val = float(baseline_val)
    if baseline_val == 0:
        return []

    intervals = []
    in_anomaly = False
    interval_start = None
    max_dev = 0.0

    for point in series:
        val = point.get("value")
        ts = point.get("timestamp", "")
        if val is None:
            continue
        dev_pct = abs((val - baseline_val) / baseline_val) * 100

        if dev_pct >= threshold_pct:
            if not in_anomaly:
                in_anomaly = True
                interval_start = ts
                max_dev = dev_pct
            else:
                max_dev = max(max_dev, dev_pct)
        else:
            if in_anomaly:
                intervals.append({
                    "start": interval_start,
                    "end": ts,
                    "max_deviation_pct": round(max_dev, 2),
                })
                in_anomaly = False
                max_dev = 0.0

    # Close open interval
    if in_anomaly and series:
        intervals.append({
            "start": interval_start,
            "end": series[-1].get("timestamp", ""),
            "max_deviation_pct": round(max_dev, 2),
        })

    return intervals


def export_metrics_csv(series: list, metric_name: str) -> str:
    """Return a CSV string for the given time-series.

    Header: timestamp,value,metric
    """
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "value", "metric"])
    for point in series:
        writer.writerow([
            point.get("timestamp", ""),
            point.get("value", ""),
            metric_name,
        ])
    return output.getvalue()
