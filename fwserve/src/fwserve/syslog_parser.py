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

# Cisco IOS format: "seqno: hostname: seqno: *timestamp: %FACILITY-SEV-MNEMONIC: message"
# Example: "90: SITE1-Gateway: 000092: *Jan 23 00:59:32.649 EST: %SYS-5-CONFIG_I: ..."
CISCO_IOS_PATTERN = re.compile(
    r"^(?:\d+:\s+)?(?P<host>[A-Za-z0-9_-]+):\s*(?:\d+:\s+)?\*?"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)"
    r"(?:\s+[A-Z]{3})?:\s*(?P<msg>.*)$"
)

# Patterns to filter out (SSH/Login/Config noise)
IGNORED_MESSAGE_PATTERNS = [
    r"%SSH-5-SSH2_SESSION",
    r"%SSH-5-SSH2_USERAUTH",
    r"%SSH-5-SSH2_CLOSE",
    r"%SYS-6-LOGOUT",
    r"%SEC_LOGIN-5-LOGIN_SUCCESS",
    r"%SYS-5-CONFIG_I",
    r"%PARSER-5-CFGLOG_LOGGEDCMD",
    r"%SYS-6-PRIVCFG_ENCRYPT_SUCCESS",
    r"%SYS-6-TTY_EXPIRE_TIMER",
    r"%SYS-5-CONFIG_P.*SEP_webui_wsma_http",  # Web UI config changes
    r"%SYS-4-LOGGINGHOST_STARTSTOP",  # Logging start/stop messages
]


def should_filter_message(message: str) -> bool:
    """Check if a syslog message should be filtered out.

    Args:
        message: The syslog message text to check.

    Returns:
        True if the message should be filtered (ignored), False otherwise.
    """
    for pattern in IGNORED_MESSAGE_PATTERNS:
        if re.search(pattern, message, re.IGNORECASE):
            return True
    return False


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


def _parse_cisco_ios(rest: str) -> dict[str, Any] | None:
    """Parse Cisco IOS/IOS-XE syslog format.

    Format: "seqno: hostname: seqno: *timestamp: %FACILITY-SEV-MNEMONIC: message"
    Example: "90: SITE1-Gateway: 000092: *Jan 23 00:59:32.649 EST: %SYS-5-CONFIG_I: ..."
    """
    match = CISCO_IOS_PATTERN.match(rest)
    if not match:
        return None

    ts_text = match.group("ts")
    host = match.group("host")
    msg = match.group("msg").strip()

    # Parse timestamp (may include milliseconds)
    parsed_ts = None
    try:
        now = datetime.now(config.TIMEZONE)
        # Remove milliseconds for parsing
        ts_clean = re.sub(r"\.\d+", "", ts_text)
        ts_with_year = f"{now.year} {ts_clean}"
        naive_ts = datetime.strptime(ts_with_year, "%Y %b %d %H:%M:%S")
        parsed_ts = naive_ts.replace(tzinfo=config.TIMEZONE)
    except ValueError:
        parsed_ts = None

    return {
        "timestamp": parsed_ts.isoformat() if parsed_ts else None,
        "host": host,
        "message": msg,
    }


def parse_syslog_message(params: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a syslog message into a normalized entry.

    Args:
        params: Dict containing `raw` syslog message string and optional `source` IP.

    Returns:
        Dict containing normalized syslog entry fields, or None if filtered.
    """
    raw = params.get("raw", "")
    source_ip = params.get("source", "unknown")
    received_at = _now_iso()
    priority_result = _parse_priority(raw)
    pri = priority_result["pri"]
    rest = priority_result["rest"]

    # Try parsers in order: RFC5424, Cisco IOS, RFC3164
    parsed = _parse_rfc5424(rest) or _parse_cisco_ios(rest) or _parse_rfc3164(rest)
    # Use parsed hostname if available, otherwise fall back to source IP
    host = parsed["host"] if parsed else source_ip
    message = parsed["message"] if parsed else rest
    timestamp = parsed["timestamp"] if parsed else None

    # Filter out noise messages if filtering is enabled
    if config.SYSLOG_FILTER_NOISE and should_filter_message(message):
        return None

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
