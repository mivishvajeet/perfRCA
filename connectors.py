"""Connector interfaces and status registry for external integrations."""

import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


# Connector definitions: name -> required env vars, health URL env var
_CONNECTOR_DEFS = {
    "prometheus": {
        "type": "metrics",
        "required_env": ["PROMETHEUS_URL"],
        "url_env": "PROMETHEUS_URL",
        "health_path": "/-/healthy",
    },
    "elasticsearch": {
        "type": "search",
        "required_env": ["ES_URL"],
        "url_env": "ES_URL",
        "health_path": "/_cluster/health",
    },
    "jaeger": {
        "type": "tracing",
        "required_env": ["JAEGER_URL"],
        "url_env": "JAEGER_URL",
        "health_path": "/",
    },
    "github": {
        "type": "vcs",
        "required_env": ["GITHUB_TOKEN"],
        "url_env": None,
        "health_url": "https://api.github.com",
        "health_path": "/",
    },
    "jira": {
        "type": "ticketing",
        "required_env": ["JIRA_URL", "JIRA_TOKEN"],
        "url_env": "JIRA_URL",
        "health_path": "/rest/api/2/serverInfo",
    },
    "confluence": {
        "type": "documentation",
        "required_env": ["CONFLUENCE_URL", "CONFLUENCE_TOKEN"],
        "url_env": "CONFLUENCE_URL",
        "health_path": "/rest/api/space",
    },
    "alertmanager": {
        "type": "alerting",
        "required_env": ["ALERTMANAGER_URL"],
        "url_env": "ALERTMANAGER_URL",
        "health_path": "/-/healthy",
    },
}


@dataclass
class ConnectorStatus:
    name: str
    type: str
    configured: bool
    healthy: Optional[bool]
    last_check: Optional[str]
    error: Optional[str]
    config_keys_present: list = field(default_factory=list)


def _is_private_url(url: str) -> bool:
    """Return True if the URL resolves to a private/loopback/reserved address (SSRF check)."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower()
        if not hostname:
            return True
        if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::"):
            return True
        if hostname.endswith(".local") or hostname.endswith(".internal"):
            return True

        # Check direct IP literal
        try:
            addr = ipaddress.ip_address(hostname)
            return (addr.is_private or addr.is_loopback or addr.is_link_local or
                    addr.is_reserved or addr.is_multicast or addr.is_unspecified)
        except ValueError:
            pass

        # Perform DNS resolution to check for rebinding / aliases pointing to private IPs
        try:
            addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                addr = ipaddress.ip_address(ip_str)
                if (addr.is_private or addr.is_loopback or addr.is_link_local or
                        addr.is_reserved or addr.is_multicast or addr.is_unspecified):
                    return True
        except (socket.gaierror, socket.herror, OSError):
            pass

        return False
    except Exception:
        return False


def _safe_url(url: str) -> str:
    """Raise ValueError if URL is unsafe (SSRF protection)."""
    allow_private = os.environ.get("ALLOW_PRIVATE_URLS", "").lower() in ("1", "true", "yes")
    if not allow_private and _is_private_url(url):
        raise ValueError(f"SSRF protection: URL '{url}' points to a private/loopback address.")
    return url


class ConnectorRegistry:
    """Reads connector config from env vars or a JSON config file."""

    def __init__(self, project_root=None):
        self.project_root = Path(project_root) if project_root else Path(".")
        self._file_config = self._load_file_config()

    def _load_file_config(self) -> dict:
        config_path = self.project_root / "connectors_config.json"
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _get_env(self, key: str) -> Optional[str]:
        """Get from env first, then file config."""
        return os.environ.get(key) or self._file_config.get(key)

    def _build_status(self, name: str) -> ConnectorStatus:
        defn = _CONNECTOR_DEFS[name]
        present = [k for k in defn["required_env"] if self._get_env(k)]
        configured = len(present) == len(defn["required_env"])
        return ConnectorStatus(
            name=name,
            type=defn["type"],
            configured=configured,
            healthy=None,
            last_check=None,
            error=None,
            config_keys_present=present,
        )

    def get_status(self, name: str) -> Optional[ConnectorStatus]:
        if name not in _CONNECTOR_DEFS:
            return None
        return self._build_status(name)

    def list_all_statuses(self) -> list:
        return [asdict(self._build_status(name)) for name in _CONNECTOR_DEFS]

    def test_connector(self, name: str) -> dict:
        """Test a connector. Returns {"ok": bool, "message": str, "latency_ms": int}."""
        if name not in _CONNECTOR_DEFS:
            return {"ok": False, "message": f"Unknown connector '{name}'.", "latency_ms": 0}

        defn = _CONNECTOR_DEFS[name]
        present = [k for k in defn["required_env"] if self._get_env(k)]
        configured = len(present) == len(defn["required_env"])

        if not configured:
            missing = [k for k in defn["required_env"] if k not in present]
            return {
                "ok": False,
                "message": f"Connector '{name}' is not configured. Missing env vars: {', '.join(missing)}.",
                "latency_ms": 0,
            }

        # Build test URL
        if defn.get("url_env"):
            base_url = self._get_env(defn["url_env"]).rstrip("/")
        elif defn.get("health_url"):
            base_url = defn["health_url"].rstrip("/")
        else:
            return {"ok": False, "message": f"No URL configured for '{name}'.", "latency_ms": 0}

        health_path = defn.get("health_path", "/")
        test_url = base_url + health_path

        # SSRF protection
        try:
            _safe_url(test_url)
        except ValueError as e:
            return {"ok": False, "message": str(e), "latency_ms": 0}

        # Perform HTTP GET
        start = time.monotonic()
        try:
            req = urllib.request.Request(test_url, headers={"User-Agent": "perfRCA-connector-check/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                latency_ms = int((time.monotonic() - start) * 1000)
                return {
                    "ok": resp.status < 400,
                    "message": f"HTTP {resp.status} from {test_url}",
                    "latency_ms": latency_ms,
                }
        except urllib.error.HTTPError as e:
            latency_ms = int((time.monotonic() - start) * 1000)
            return {
                "ok": False,
                "message": f"HTTP error {e.code} from {test_url}",
                "latency_ms": latency_ms,
            }
        except Exception as e:
            latency_ms = int((time.monotonic() - start) * 1000)
            return {
                "ok": False,
                "message": f"Connection failed: {e}",
                "latency_ms": latency_ms,
            }
