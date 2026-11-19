"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store a sanitized input and its start time for later matching."""
        key = request_id or user_id
        self._open[key] = (time.monotonic(), utc_now_iso(), user_id, _sanitize(text))

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Append one completed request without storing raw credentials."""
        key = request_id or user_id
        started = self._open.pop(key, None)
        self.logs.append({
            "request_id": request_id,
            "user_id": user_id,
            "timestamp": started[1] if started else utc_now_iso(),
            "input": started[3] if started else "",
            "output": _sanitize(text),
            "blocked": blocked,
            "layer": layer,
            "latency_ms": round((time.monotonic() - started[0]) * 1000, 2) if started else None,
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        # TODO: path = filepath or default_audit_log_path()
        #       ensure parent dirs exist, dump self.logs with indent=2
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")


def _sanitize(text: str) -> str:
    from guardrails.output_guardrails import content_filter
    redacted = content_filter(text)["redacted"]
    return re.sub(r"\bliquid_[A-Za-z0-9_-]+\b", "[REDACTED]", redacted)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
