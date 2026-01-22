"""Unit tests for syslog helpers."""

import tempfile
from pathlib import Path

import pytest

from fwserve.syslog_parser import parse_syslog_message
from fwserve.syslog_server import start_syslog_listeners, stop_syslog_listeners
from fwserve.syslog_store import append_syslog_entry, create_syslog_store, get_syslog_tail


class TestSyslogParser:
    """Tests for syslog parsing."""

    def test_parse_rfc3164(self) -> None:
        raw = "<34>Oct 11 22:14:15 host1 app: message here"
        result = parse_syslog_message({"raw": raw})

        assert result["host"] == "host1"
        assert result["severity"] == 2
        assert result["severity_label"] == "crit"
        assert "message here" in result["message"]

    def test_parse_rfc5424(self) -> None:
        raw = "<165>1 2023-10-11T22:14:15Z host2 app 123 ID - hello world"
        result = parse_syslog_message({"raw": raw})

        assert result["host"] == "host2"
        assert result["severity"] == 5
        assert result["severity_label"] == "notice"
        assert "hello world" in result["message"]


class TestSyslogStore:
    """Tests for syslog storage."""

    @pytest.mark.asyncio
    async def test_append_and_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "syslog.log"
            store = create_syslog_store({"file_path": file_path, "tail_size": 5})["store"]

            entry = {"host": "host1", "message": "hello", "severity": 6}
            await append_syslog_entry({"store": store, "entry": entry})

            result = get_syslog_tail({"store": store, "limit": 10, "filters": {}})
            assert len(result["entries"]) == 1
            assert result["entries"][0]["message"] == "hello"

    def test_tail_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "syslog.log"
            store = create_syslog_store({"file_path": file_path, "tail_size": 5})["store"]
            store["tail"].extend(
                [
                    {"host": "alpha", "message": "ok", "severity": 6},
                    {
                        "host": "beta",
                        "message": "bad error",
                        "severity": 3,
                        "severity_label": "err",
                    },
                ]
            )

            result = get_syslog_tail(
                {
                    "store": store,
                    "limit": 10,
                    "filters": {"host": "beta", "severity": "err", "q": "bad"},
                }
            )
            assert len(result["entries"]) == 1
            assert result["entries"][0]["host"] == "beta"


class TestSyslogServer:
    """Tests for syslog server startup/shutdown."""

    @pytest.mark.asyncio
    async def test_start_stop_no_listeners(self) -> None:
        listeners = await start_syslog_listeners(
            {
                "on_message": lambda payload: None,
                "enable_udp": False,
                "enable_tcp": False,
                "udp_port": 5514,
                "tcp_port": 5514,
                "max_bytes": 1024,
            }
        )

        assert listeners["udp_transport"] is None
        assert listeners["tcp_server"] is None

        # stop_syslog_listeners returns None, just verify it completes
        await stop_syslog_listeners(listeners)
