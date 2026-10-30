"""Persistent store for incidents, alerts, saved searches, and case history."""

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _uuid():
    return str(uuid.uuid4())


class PlatformStore:
    """SQLite-backed persistence for the observability platform."""

    def __init__(self, db_path):
        self.db_path = str(db_path)
        self._create_tables()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _create_tables(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    service TEXT,
                    severity TEXT,
                    status TEXT DEFAULT 'open',
                    owner TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    description TEXT,
                    rca_investigation_id TEXT
                );

                CREATE TABLE IF NOT EXISTS incident_events (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    actor TEXT,
                    message TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id)
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    service TEXT,
                    condition_metric TEXT,
                    threshold REAL,
                    operator TEXT,
                    severity TEXT,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_fired_at TEXT,
                    status TEXT DEFAULT 'inactive'
                );

                CREATE TABLE IF NOT EXISTS saved_searches (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    query TEXT,
                    filters_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT,
                    service TEXT,
                    symptoms_json TEXT,
                    fingerprint_json TEXT,
                    findings_json TEXT,
                    fix_applied TEXT,
                    status TEXT DEFAULT 'pending',
                    recorded_at TEXT NOT NULL,
                    confirmed_at TEXT,
                    confirmed_by TEXT
                );
            """)

    # ── Incident CRUD ────────────────────────────────────────────────────

    def create_incident(self, title, service=None, severity=None, description=None, owner=None):
        """Create a new incident. Returns the created incident dict."""
        now = _now_iso()
        incident_id = _uuid()
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO incidents
                       (id, title, service, severity, status, owner, created_at, updated_at, description)
                       VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?)""",
                    (incident_id, title, service, severity, owner, now, now, description)
                )
            return self.get_incident(incident_id)
        except sqlite3.IntegrityError:
            return None

    def get_incident(self, incident_id):
        """Return incident dict or None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_incidents(self, filters=None):
        """Return list of incident dicts, optionally filtered by status/severity/service."""
        filters = filters or {}
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if filters.get("status"):
            query += " AND status = ?"
            params.append(filters["status"])
        if filters.get("severity"):
            query += " AND severity = ?"
            params.append(filters["severity"])
        if filters.get("service"):
            query += " AND service = ?"
            params.append(filters["service"])
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_incident_status(self, incident_id, status, extra=None):
        """Update incident status (and optionally other fields). Returns updated dict."""
        now = _now_iso()
        extra = extra or {}
        fields = ["status = ?", "updated_at = ?"]
        values = [status, now]
        allowed_extra = {"owner", "rca_investigation_id", "description"}
        for key, val in extra.items():
            if key in allowed_extra:
                fields.append(f"{key} = ?")
                values.append(val)
        values.append(incident_id)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE incidents SET {', '.join(fields)} WHERE id = ?", values
            )
        return self.get_incident(incident_id)

    def add_incident_event(self, incident_id, event_type, actor=None, message=None):
        """Add a timeline event to an incident."""
        event_id = _uuid()
        now = _now_iso()
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO incident_events
                       (id, incident_id, event_type, actor, message, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (event_id, incident_id, event_type, actor, message, now)
                )
            return {"id": event_id, "incident_id": incident_id, "event_type": event_type,
                    "actor": actor, "message": message, "timestamp": now}
        except sqlite3.IntegrityError:
            return None

    def get_incident_timeline(self, incident_id):
        """Return list of timeline event dicts for an incident."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM incident_events WHERE incident_id = ? ORDER BY timestamp ASC",
                (incident_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Alert CRUD ───────────────────────────────────────────────────────

    def create_alert(self, name, service=None, condition_metric=None, threshold=None,
                     operator=None, severity=None, enabled=True):
        """Create a new alert rule."""
        alert_id = _uuid()
        now = _now_iso()
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO alerts
                       (id, name, service, condition_metric, threshold, operator,
                        severity, enabled, created_at, status)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'inactive')""",
                    (alert_id, name, service, condition_metric, threshold, operator,
                     severity, 1 if enabled else 0, now)
                )
            return self._get_alert(alert_id)
        except sqlite3.IntegrityError:
            return None

    def _get_alert(self, alert_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if row:
            d = dict(row)
            d["enabled"] = bool(d["enabled"])
            return d
        return None

    def list_alerts(self, service=None):
        """Return list of alert dicts, optionally filtered by service."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if service:
            query += " AND service = ?"
            params.append(service)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d["enabled"])
            result.append(d)
        return result

    def update_alert(self, alert_id, updates):
        """Update alert fields. Returns updated dict."""
        allowed = {"name", "service", "condition_metric", "threshold", "operator",
                   "severity", "enabled", "status"}
        fields = []
        values = []
        for key, val in updates.items():
            if key in allowed:
                fields.append(f"{key} = ?")
                if key == "enabled":
                    values.append(1 if val else 0)
                else:
                    values.append(val)
        if not fields:
            return self._get_alert(alert_id)
        values.append(alert_id)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE alerts SET {', '.join(fields)} WHERE id = ?", values
            )
        return self._get_alert(alert_id)

    def fire_alert(self, alert_id):
        """Mark alert as fired with current timestamp."""
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                "UPDATE alerts SET last_fired_at = ?, status = 'firing' WHERE id = ?",
                (now, alert_id)
            )
        return self._get_alert(alert_id)

    # ── Saved Searches ───────────────────────────────────────────────────

    def save_search(self, name, query=None, filters=None):
        """Save a search. Returns saved search dict."""
        search_id = _uuid()
        now = _now_iso()
        filters_json = json.dumps(filters or {})
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO saved_searches (id, name, query, filters_json, created_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (search_id, name, query, filters_json, now)
                )
            return {"id": search_id, "name": name, "query": query,
                    "filters": filters or {}, "created_at": now}
        except sqlite3.IntegrityError:
            return None

    def list_saved_searches(self):
        """Return list of saved search dicts."""
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM saved_searches ORDER BY created_at DESC").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["filters"] = json.loads(d.pop("filters_json", "{}") or "{}")
            except (json.JSONDecodeError, TypeError):
                d["filters"] = {}
            result.append(d)
        return result

    # ── Cases ────────────────────────────────────────────────────────────

    def save_case(self, investigation_id, service=None, symptoms=None,
                  fingerprint=None, findings=None, fix_applied=None):
        """Save an RCA case. Returns saved case dict."""
        case_id = _uuid()
        now = _now_iso()
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO cases
                       (id, investigation_id, service, symptoms_json, fingerprint_json,
                        findings_json, fix_applied, status, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                    (case_id, investigation_id, service,
                     json.dumps(symptoms or {}),
                     json.dumps(fingerprint or {}),
                     json.dumps(findings or {}),
                     fix_applied, now)
                )
            return self._get_case(case_id)
        except sqlite3.IntegrityError:
            return None

    def confirm_case(self, case_id, confirmed_by=None, fix_applied=None):
        """Confirm a root cause case."""
        now = _now_iso()
        fields = ["status = 'confirmed'", "confirmed_at = ?"]
        values = [now]
        if confirmed_by:
            fields.append("confirmed_by = ?")
            values.append(confirmed_by)
        if fix_applied is not None:
            fields.append("fix_applied = ?")
            values.append(fix_applied)
        values.append(case_id)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE cases SET {', '.join(fields)} WHERE id = ?", values
            )
        return self._get_case(case_id)

    def _get_case(self, case_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        if row:
            return self._parse_case(dict(row))
        return None

    def _parse_case(self, d):
        for field in ("symptoms_json", "fingerprint_json", "findings_json"):
            key = field.replace("_json", "")
            try:
                d[key] = json.loads(d.pop(field, "{}") or "{}")
            except (json.JSONDecodeError, TypeError):
                d[key] = {}
        return d

    def list_cases(self, filters=None):
        """Return list of case dicts."""
        filters = filters or {}
        query = "SELECT * FROM cases WHERE 1=1"
        params = []
        if filters.get("service"):
            query += " AND service = ?"
            params.append(filters["service"])
        if filters.get("status"):
            query += " AND status = ?"
            params.append(filters["status"])
        query += " ORDER BY recorded_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._parse_case(dict(r)) for r in rows]

    def search_cases_by_symptom(self, service=None, symptom_keyword=None):
        """Search cases by service and/or symptom keyword in symptoms_json."""
        query = "SELECT * FROM cases WHERE 1=1"
        params = []
        if service:
            query += " AND service = ?"
            params.append(service)
        if symptom_keyword:
            query += " AND symptoms_json LIKE ?"
            params.append(f"%{symptom_keyword}%")
        query += " ORDER BY recorded_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._parse_case(dict(r)) for r in rows]

    def ping(self):
        """Health check — returns True if DB is reachable."""
        try:
            with self._connect() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False
