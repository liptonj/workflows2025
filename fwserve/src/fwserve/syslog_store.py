"""Syslog storage with file persistence and in-memory tail."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def create_syslog_store(params: dict[str, Any]) -> dict[str, Any]:
    """Create a new syslog store.

    Args:
        params: Dict with file_path and optional tail_size.

    Returns:
        Dict containing the store object.
    """
    file_path = Path(params["file_path"])
    tail_size = int(params.get("tail_size", 5000))

    file_path.parent.mkdir(parents=True, exist_ok=True)
    if not file_path.exists():
        file_path.touch()

    tail: deque[dict[str, Any]] = deque(maxlen=tail_size)

    # Load existing entries into tail
    try:
        with file_path.open("r", encoding="utf-8") as file_handle:
            for line in file_handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    tail.append(entry)
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.warning("Could not load existing syslog entries: %s", exc)

    return {
        "store": {
            "file_path": file_path,
            "tail": tail,
            "lock": asyncio.Lock(),
        }
    }


async def append_syslog_entry(params: dict[str, Any]) -> dict[str, bool]:
    """Append a syslog entry to the store.

    Args:
        params: Dict with store and entry.

    Returns:
        Dict with is_success boolean.
    """
    store = params["store"]
    entry = params["entry"]
    file_path: Path = store["file_path"]
    tail: deque[dict[str, Any]] = store["tail"]
    lock: asyncio.Lock = store["lock"]

    async with lock:
        tail.append(entry)
        try:
            with file_path.open("a", encoding="utf-8") as file_handle:
                file_handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.error("Failed to write syslog entry: %s", exc)
            return {"is_success": False}

    return {"is_success": True}


def get_syslog_tail(params: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Get the most recent syslog entries.

    Args:
        params: Dict with store, optional limit, and optional filters.

    Returns:
        Dict with entries list.
    """
    store = params["store"]
    limit = int(params.get("limit", 500))
    filters = params.get("filters", {})
    tail: deque[dict[str, Any]] = store["tail"]

    host_filter = str(filters.get("host", "")).strip().lower()
    severity_filter = str(filters.get("severity", "")).strip().lower()
    message_filter = str(filters.get("q", "")).strip().lower()

    results: list[dict[str, Any]] = []
    for entry in tail:
        if host_filter and host_filter not in str(entry.get("host", "")).lower():
            continue
        if severity_filter:
            severity_label = str(entry.get("severity_label") or "").lower()
            severity_value = entry.get("severity")
            if severity_filter != severity_label and severity_filter != str(severity_value):
                continue
        if message_filter and message_filter not in str(entry.get("message", "")).lower():
            continue
        results.append(entry)

    return {"entries": results[-limit:]}
