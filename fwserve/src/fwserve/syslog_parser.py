"""Syslog parsing helpers."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from fwserve import config

SEVERITY_LABELS = [
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
]

RFC3164_PATTERN = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<msg>.*)$"
)


def _now_iso() -> str:
    """Get current time in configured timezone as ISO format string."""
    return datetime.now(config.TIMEZONE).isoformat()


def _parse_priority(raw: str) -> dict[str, Any]:
    if not raw.startswith("<"):
        return {"pri": None, "rest": raw}

    end_idx = raw.find(">")
    if end_idx == -1:
        return {"pri": None, "rest": raw}

    pri_text = raw[1:end_idx]
    if not pri_text.isdigit():
        return {"pri": None, "rest": raw}

    pri = int(pri_text)
    return {"pri": pri, "rest": raw[end_idx + 1 :].lstrip()}


def _parse_rfc5424(rest: str) -> dict[str, Any] | None:
    parts = rest.split(" ", 6)
    if len(parts) < 7:
        return None

    version = parts[0]
    if not version.isdigit():
        return None

    timestamp = parts[1]
    host = parts[2]
    msg = parts[6]

    parsed_ts = None
    try:
        parsed_ts = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        parsed_ts = None

    return {
        "timestamp": parsed_ts.isoformat() if parsed_ts else None,
        "host": host,
        "message": msg,
    }


def _parse_rfc3164(rest: str) -> dict[str, Any] | None:
    match = RFC3164_PATTERN.match(rest)
    if not match:
        return None

    ts_text = match.group("ts")
    host = match.group("host")
    msg = match.group("msg")

    parsed_ts = None
    try:
        now = datetime.now(config.TIMEZONE)
        ts_with_year = f"{now.year} {ts_text}"
        naive_ts = datetime.strptime(ts_with_year, "%Y %b %d %H:%M:%S")
        parsed_ts = naive_ts.replace(tzinfo=config.TIMEZONE)
    except ValueError:
        parsed_ts = None

    return {
        "timestamp": parsed_ts.isoformat() if parsed_ts else None,
        "host": host,
        "message": msg,
    }


def parse_syslog_message(params: dict[str, Any]) -> dict[str, Any]:
    """Parse a syslog message into a normalized entry.

    Args:
        params: Dict containing `raw` syslog message string.

    Returns:
        Dict containing normalized syslog entry fields.
    """
    raw = params.get("raw", "")
    received_at = _now_iso()
    priority_result = _parse_priority(raw)
    pri = priority_result["pri"]
    rest = priority_result["rest"]

    parsed = _parse_rfc5424(rest) or _parse_rfc3164(rest)
    host = parsed["host"] if parsed else "unknown"
    message = parsed["message"] if parsed else rest
    timestamp = parsed["timestamp"] if parsed else None

    severity = None
    facility = None
    severity_label = None
    if pri is not None:
        severity = pri % 8
        facility = pri // 8
        if 0 <= severity < len(SEVERITY_LABELS):
            severity_label = SEVERITY_LABELS[severity]

    return {
        "received_at": received_at,
        "timestamp": timestamp or received_at,
        "host": host,
        "message": message,
        "raw": raw,
        "priority": pri,
        "severity": severity,
        "severity_label": severity_label,
        "facility": facility,
    }
