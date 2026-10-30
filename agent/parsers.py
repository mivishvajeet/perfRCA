"""Log parsing and normalization for the observability platform."""

import json
import re
import uuid
from datetime import datetime, timezone

# Canonical severity levels
_SEVERITY_MAP = {
    "ERROR": "ERROR",
    "ERR": "ERROR",
    "WARN": "WARN",
    "WARNING": "WARN",
    "INFO": "INFO",
    "DEBUG": "DEBUG",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "TRACE": "DEBUG",
}

_SEVERITY_ORDER = ["CRITICAL", "ERROR", "WARN", "INFO", "DEBUG", "UNKNOWN"]


def _new_uuid():
    return str(uuid.uuid4())


def _normalize_severity(raw: str) -> str:
    if not raw:
        return "UNKNOWN"
    return _SEVERITY_MAP.get(raw.upper().strip(), "UNKNOWN")


def _empty_event(source: str = "") -> dict:
    return {
        "id": _new_uuid(),
        "timestamp": "",
        "severity": "UNKNOWN",
        "service": "",
        "environment": "",
        "host": "",
        "source": source,
        "message": "",
        "structured_fields": {},
        "trace_id": None,
        "span_id": None,
        "request_id": None,
        "exception_type": None,
        "stack_trace": None,
        "original": "",
        "parse_error": None,
        "status": "parsed",
    }


def _extract_special_fields(d: dict) -> dict:
    """Pull trace/span/request IDs and exception info from a dict."""
    trace_id = d.get("trace_id") or d.get("traceId") or d.get("trace")
    span_id = d.get("span_id") or d.get("spanId") or d.get("span")
    request_id = (d.get("request_id") or d.get("requestId") or
                  d.get("req_id") or d.get("request"))
    exception_type = (d.get("exception_type") or d.get("exception") or
                      d.get("error_type") or d.get("errorType"))
    stack_trace = d.get("stack_trace") or d.get("stackTrace") or d.get("stack")
    return {
        "trace_id": str(trace_id) if trace_id else None,
        "span_id": str(span_id) if span_id else None,
        "request_id": str(request_id) if request_id else None,
        "exception_type": str(exception_type) if exception_type else None,
        "stack_trace": str(stack_trace) if stack_trace else None,
    }


def parse_json_log(entry: dict) -> dict:
    """Normalize an existing JSON log entry to canonical schema."""
    original = json.dumps(entry, default=str)
    event = _empty_event("json_fixture")
    event["original"] = original

    # Timestamp
    ts = entry.get("timestamp") or entry.get("time") or entry.get("@timestamp") or ""
    event["timestamp"] = str(ts)

    # Severity
    raw_level = entry.get("level") or entry.get("severity") or entry.get("lvl") or ""
    event["severity"] = _normalize_severity(str(raw_level))

    # Service
    event["service"] = str(entry.get("service") or entry.get("svc") or "")

    # Environment / host
    event["environment"] = str(entry.get("environment") or entry.get("env") or "")
    event["host"] = str(entry.get("host") or entry.get("hostname") or "")

    # Message
    event["message"] = str(entry.get("message") or entry.get("msg") or "")

    # Special fields
    event.update(_extract_special_fields(entry))

    # Structured fields: everything else
    skip = {"timestamp", "time", "@timestamp", "level", "severity", "lvl",
            "service", "svc", "environment", "env", "host", "hostname",
            "message", "msg", "trace_id", "traceId", "trace", "span_id",
            "spanId", "span", "request_id", "requestId", "req_id", "request",
            "exception_type", "exception", "error_type", "errorType",
            "stack_trace", "stackTrace", "stack"}
    event["structured_fields"] = {k: v for k, v in entry.items() if k not in skip}

    if event.get("parse_error"):
        event["status"] = "partial" if (event.get("timestamp") or event.get("message")) else "malformed"
    else:
        event["status"] = "parsed"

    return event


# Patterns for text log parsing
_ISO_TS_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)
_LEVEL_RE = re.compile(r'\[?(ERROR|WARN(?:ING)?|INFO|DEBUG|CRITICAL|FATAL|TRACE)\]?', re.IGNORECASE)
_SERVICE_MSG_RE = re.compile(r'^([\w.\-]+):\s*(.*)', re.DOTALL)
_PY_TRACEBACK_RE = re.compile(
    r'(?:Traceback \(most recent call last\):.*?\n)?(?P<exc_type>[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Warning)):\s*(?P<exc_msg>.*)',
    re.DOTALL
)
_JAVA_EXC_RE = re.compile(
    r'(?P<exc_type>(?:[a-zA-Z_][a-zA-Z0-9_]*\.)+[a-zA-Z_][a-zA-Z0-9_]*(?:Exception|Error)):?\s*(?P<exc_msg>.*)',
    re.DOTALL
)


def parse_text_line(line: str) -> dict:
    """Parse a common text log line to canonical schema."""
    event = _empty_event("uploaded_text")
    event["original"] = line
    rest = line

    # Extract ISO timestamp
    m = _ISO_TS_RE.match(rest)
    if m:
        event["timestamp"] = m.group(1)
        rest = rest[m.end():].strip()

    # Extract log level
    m = _LEVEL_RE.match(rest)
    if m:
        event["severity"] = _normalize_severity(m.group(1))
        rest = rest[m.end():].strip()
        # strip leading punctuation like ] or -
        rest = rest.lstrip("]-: ").strip()
    else:
        event["severity"] = "INFO"

    # Check for Java exception or Python traceback patterns
    if "Traceback" in rest or "Exception" in rest or "Error" in rest or "\tat " in rest:
        jv_m = _JAVA_EXC_RE.search(rest)
        if jv_m:
            event["exception_type"] = jv_m.group("exc_type")
            event["stack_trace"] = rest
            if event["severity"] in ("INFO", "UNKNOWN"):
                event["severity"] = "ERROR"
        else:
            py_m = _PY_TRACEBACK_RE.search(rest)
            if py_m:
                event["exception_type"] = py_m.group("exc_type")
                event["stack_trace"] = rest
                if event["severity"] in ("INFO", "UNKNOWN"):
                    event["severity"] = "ERROR"

    # Extract service: message pattern
    m = _SERVICE_MSG_RE.match(rest)
    if m:
        event["service"] = m.group(1)
        event["message"] = m.group(2).strip()
    else:
        event["message"] = rest.strip()

    if not event["timestamp"]:
        event["parse_error"] = "no_timestamp"
        event["status"] = "partial" if event.get("message") else "malformed"
    else:
        event["status"] = "parsed"

    return event


# Nginx combined log format:
# 1.2.3.4 - - [27/Oct/2026:09:15:00 +0000] "GET /path HTTP/1.1" 200 512 "-" "Mozilla/5.0"
_NGINX_RE = re.compile(
    r'^(?P<remote_addr>\S+)\s+'
    r'\S+\s+\S+\s+'
    r'\[(?P<time_local>[^\]]+)\]\s+'
    r'"(?P<request>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<body_bytes_sent>\d+)\s+'
    r'"(?P<http_referer>[^"]*)"\s+'
    r'"(?P<http_user_agent>[^"]*)"'
)
_NGINX_TS_RE = re.compile(r'(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})')
_MONTHS = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"
}


def _nginx_ts_to_iso(ts_str: str) -> str:
    """Convert '27/Oct/2026:09:15:00 +0000' to ISO 8601."""
    try:
        # e.g. 27/Oct/2026:09:15:00 +0000
        parts = ts_str.split(":")
        date_part = parts[0]  # 27/Oct/2026
        time_part = ":".join(parts[1:3])  # 09:15
        sec_tz = parts[3]   # 00 +0000
        sec, tz = sec_tz.split(" ", 1)
        day, month_str, year = date_part.split("/")
        month = _MONTHS.get(month_str, "01")
        tz_clean = tz.replace("+0000", "Z").replace("+00:00", "Z")
        return f"{year}-{month}-{day}T{time_part}:{sec}{tz_clean}"
    except Exception:
        return ts_str


def parse_nginx_line(line: str) -> dict:
    """Parse an nginx combined access log line."""
    event = _empty_event("nginx")
    event["original"] = line
    m = _NGINX_RE.match(line)
    if not m:
        event["message"] = line
        event["parse_error"] = "nginx_parse_failed"
        event["status"] = "malformed"
        return event

    g = m.groupdict()
    raw_ts = g.get("time_local", "")
    event["timestamp"] = _nginx_ts_to_iso(raw_ts)

    status = int(g.get("status", 0))
    if status >= 500:
        event["severity"] = "ERROR"
    elif status >= 400:
        event["severity"] = "WARN"
    else:
        event["severity"] = "INFO"

    event["message"] = f"{g.get('request', '')} -> {status}"
    event["structured_fields"] = {
        "remote_addr": g["remote_addr"],
        "status": status,
        "body_bytes_sent": int(g.get("body_bytes_sent", 0)),
        "http_referer": g.get("http_referer", ""),
        "http_user_agent": g.get("http_user_agent", ""),
        "request": g.get("request", ""),
    }
    event["service"] = "nginx"
    event["status"] = "parsed"
    return event


_LOGFMT_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_logfmt_line(line: str) -> dict:
    """Parse a key=value logfmt line."""
    event = _empty_event("logfmt")
    event["original"] = line
    fields = {}
    for key, val in _LOGFMT_RE.findall(line):
        val = val.strip('"')
        fields[key] = val

    if not fields:
        event["message"] = line
        event["parse_error"] = "logfmt_no_fields"
        event["status"] = "malformed"
        return event

    event["timestamp"] = fields.pop("ts", fields.pop("time", fields.pop("timestamp", "")))
    raw_level = fields.pop("level", fields.pop("lvl", fields.pop("severity", "")))
    event["severity"] = _normalize_severity(raw_level)
    event["service"] = fields.pop("service", fields.pop("svc", ""))
    event["host"] = fields.pop("host", "")
    event["message"] = fields.pop("msg", fields.pop("message", line))
    event.update(_extract_special_fields(fields))
    # remove extracted special fields from structured_fields
    for k in ("trace_id", "traceId", "span_id", "spanId", "request_id", "requestId"):
        fields.pop(k, None)
    event["structured_fields"] = fields
    event["status"] = "parsed"

    return event


def normalize_entries(raw_entries: list, source: str) -> dict:
    """Normalize a list of raw log entries to canonical schema.

    Returns:
        {"entries": [...], "total": int, "parse_errors": int, "skipped": int}
    """
    entries = []
    parse_errors = 0
    skipped = 0

    for raw in raw_entries:
        if raw is None:
            skipped += 1
            continue
        try:
            if isinstance(raw, dict):
                event = parse_json_log(raw)
                event["source"] = source
            elif isinstance(raw, str):
                raw_stripped = raw.strip()
                if not raw_stripped:
                    skipped += 1
                    continue
                # Detect format
                if raw_stripped.startswith("{"):
                    try:
                        d = json.loads(raw_stripped)
                        event = parse_json_log(d)
                        event["source"] = source
                    except json.JSONDecodeError:
                        event = parse_text_line(raw_stripped)
                        event["source"] = source
                elif "=" in raw_stripped and not raw_stripped.startswith("["):
                    # Could be logfmt
                    event = parse_logfmt_line(raw_stripped)
                    event["source"] = source
                else:
                    event = parse_text_line(raw_stripped)
                    event["source"] = source
            else:
                skipped += 1
                continue

            if event.get("parse_error"):
                parse_errors += 1
            entries.append(event)
        except Exception as e:
            parse_errors += 1
            skipped += 1

    return {
        "entries": entries,
        "total": len(entries),
        "parse_errors": parse_errors,
        "skipped": skipped,
    }


def search_entries(entries: list, keyword: str = "", filters: dict = None,
                   page: int = 1, page_size: int = 50) -> dict:
    """Search log entries by keyword and filters, then paginate.

    Args:
        entries: Full list of canonical log event dicts.
        keyword: Case-insensitive keyword to search in message + structured_fields + exceptions.
        filters: Dict with optional keys: severity, service, environment, from/to timestamp, status.
        page: 1-based page number.
        page_size: Number of results per page.

    Returns:
        {"results": [...], "total": int, "page": int, "pages": int}
    """
    filters = filters or {}
    keyword_lower = keyword.lower().strip() if keyword else ""

    from_ts = filters.get("from") or filters.get("from_ts") or filters.get("start_time")
    to_ts = filters.get("to") or filters.get("to_ts") or filters.get("end_time")
    status_filter = filters.get("status")

    # Filter phase
    matched = []
    for entry in entries:
        # Severity filter
        if filters.get("severity"):
            if entry.get("severity", "").upper() != filters["severity"].upper():
                continue
        # Service filter
        if filters.get("service"):
            if entry.get("service", "").lower() != filters["service"].lower():
                continue
        # Environment filter
        if filters.get("environment"):
            if entry.get("environment", "").lower() != filters["environment"].lower():
                continue
        # Status filter
        if status_filter:
            if entry.get("status", "").lower() != status_filter.lower():
                continue
        # Timestamp range bounds
        ts = entry.get("timestamp", "")
        if from_ts and ts and ts < from_ts:
            continue
        if to_ts and ts and ts > to_ts:
            continue

        # Keyword search
        if keyword_lower:
            haystack = entry.get("message", "").lower()
            sf = entry.get("structured_fields", {})
            sf_str = " ".join(str(v) for v in sf.values()).lower()
            exc_str = f"{entry.get('exception_type') or ''} {entry.get('stack_trace') or ''}".lower()
            if keyword_lower not in haystack and keyword_lower not in sf_str and keyword_lower not in exc_str:
                continue

        matched.append(entry)

    # Pagination
    total = len(matched)
    page = max(1, page)
    page_size = max(1, min(page_size, 1000))
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    start = (page - 1) * page_size
    end = start + page_size
    results = matched[start:end]

    return {
        "results": results,
        "total": total,
        "page": page,
        "pages": pages,
    }
