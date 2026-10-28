"""Anomaly detection module — explainable baseline-vs-current comparisons."""

import math


def compare_baseline(baseline, current, threshold_pct=10.0):
    """Compare baseline and current metrics; return anomalies with severity.

    Args:
        baseline: dict with 'metrics' key containing numeric metrics.
        current: dict with 'metrics' key containing numeric metrics.
        threshold_pct: minimum absolute percentage change to flag (default 10%).

    Returns:
        list of anomaly dicts, each with metric, baseline_value, current_value,
        percent_change, direction, severity, and explanation.
    """
    anomalies = []

    def _walk(obj, prefix=""):
        if not isinstance(obj, dict):
            return
        for key, val in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(val, dict):
                _walk(val, full_key)
            elif isinstance(val, (int, float)):
                # Find matching key in baseline path
                base_val = _get_nested(baseline.get("metrics", {}), full_key)
                if base_val is not None and isinstance(base_val, (int, float)):
                    anomaly = _compare_metric(full_key, base_val, val, threshold_pct)
                    if anomaly:
                        anomalies.append(anomaly)
                elif isinstance(key, str) and (key + "_ms") in str(base_val.__class__):
                    pass  # Skip; we handle the structured metrics explicitly below

    # Walk the flattened metric tree
    _walk(current.get("metrics", {}))

    return anomalies


def _get_nested(d, dotted_key):
    """Get a nested dict value by dotted key: 'latency.p50_ms'."""
    parts = dotted_key.split(".")
    for part in parts:
        if isinstance(d, dict) and part in d:
            d = d[part]
        else:
            return None
    return d


def _compare_metric(metric_name, baseline_val, current_val, threshold_pct):
    """Compare two metric values and return an anomaly dict if over threshold."""
    if baseline_val == 0 and current_val == 0:
        return None
    if baseline_val == 0:
        percent_change = 100.0 if current_val > 0 else -100.0
    else:
        percent_change = ((current_val - baseline_val) / abs(baseline_val)) * 100.0

    abs_pct = abs(percent_change)
    if abs_pct < threshold_pct:
        return None

    direction = "increase" if percent_change > 0 else "decrease"
    severity = _severity(abs_pct)

    return {
        "metric": metric_name.replace(".", "_"),
        "baseline_value": round(baseline_val, 2),
        "current_value": round(current_val, 2),
        "percent_change": round(percent_change, 1),
        "abs_percent_change": round(abs_pct, 1),
        "direction": direction,
        "severity": severity,
        "explanation": (
            f"{metric_name} {direction}d by {abs_pct:.1f}% "
            f"(from {baseline_val} to {current_val}) — severity: {severity}"
        )
    }


def _severity(abs_pct):
    """Map absolute percentage change to a severity label."""
    if abs_pct > 100:
        return "critical"
    elif abs_pct > 50:
        return "high"
    elif abs_pct > 25:
        return "medium"
    return "low"


def describe_anomalies(anomalies):
    """Return a human-readable summary of detected anomalies."""
    if not anomalies:
        return "No anomalies detected. All metrics are within normal range."

    n = len(anomalies)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in anomalies:
        sev_counts[a.get("severity", "low")] += 1

    parts = [f"{n} anomaly(s) detected:"]
    if sev_counts.get("critical"):
        parts.append(f"  {sev_counts['critical']} critical")
    if sev_counts.get("high"):
        parts.append(f"  {sev_counts['high']} high")
    if sev_counts.get("medium"):
        parts.append(f"  {sev_counts['medium']} medium")
    if sev_counts.get("low"):
        parts.append(f"  {sev_counts['low']} low")

    parts.append("")
    for a in anomalies:
        parts.append(f"  • {a['explanation']}")

    return "\n".join(parts)


def robust_summary(values):
    """Compute median and IQR for a list of numbers. Handles small N and missing values."""
    cleaned = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]
    if not cleaned:
        return {"n": 0, "median": None, "iqr": None, "q1": None, "q3": None}

    cleaned.sort()
    n = len(cleaned)

    def _percentile(data, p):
        k = (len(data) - 1) * p / 100.0
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return data[int(k)]
        return data[f] * (c - k) + data[c] * (k - f)

    return {
        "n": n,
        "median": _percentile(cleaned, 50),
        "q1": _percentile(cleaned, 25) if n >= 4 else cleaned[0],
        "q3": _percentile(cleaned, 75) if n >= 4 else cleaned[-1],
        "iqr": (_percentile(cleaned, 75) - _percentile(cleaned, 25)) if n >= 4 else 0
    }