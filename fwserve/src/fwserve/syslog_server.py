"""Syslog UDP and TCP listeners."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

logger = logging.getLogger(__name__)

OnMessageCallback = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for syslog messages."""

    def __init__(
        self,
        on_message: OnMessageCallback,
        max_bytes: int,
    ) -> None:
        self.on_message = on_message
        self.max_bytes = max_bytes

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) > self.max_bytes:
            logger.warning("Dropping oversized UDP syslog message from %s", addr)
            return

        try:
            raw = data.decode("utf-8", errors="replace").strip()
        except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            logger.warning("Failed to decode UDP syslog message: %s", exc)
            return

        asyncio.create_task(self.on_message({"raw": raw, "source": addr[0]}))


async def _handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_message: OnMessageCallback,
    max_bytes: int,
) -> None:
    addr = writer.get_extra_info("peername")
    try:
        while True:
            data = await reader.readline()
            if not data:
                break
            if len(data) > max_bytes:
                logger.warning("Dropping oversized TCP syslog message from %s", addr)
                continue
            try:
                raw = data.decode("utf-8", errors="replace").strip()
            except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
                logger.warning("Failed to decode TCP syslog message: %s", exc)
                continue
            await on_message({"raw": raw, "source": addr[0] if addr else "unknown"})
    except asyncio.CancelledError:
        pass
    except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        logger.warning("TCP syslog connection error: %s", exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001, S110  # pylint: disable=broad-exception-caught
            pass


async def start_syslog_listeners(params: dict[str, Any]) -> dict[str, Any]:
    """Start UDP and/or TCP syslog listeners.

    Args:
        params: Dict with on_message callback, enable flags, ports, and max_bytes.

    Returns:
        Dict with transport handles for cleanup.
    """
    on_message: OnMessageCallback = params["on_message"]
    enable_udp: bool = params.get("enable_udp", True)
    enable_tcp: bool = params.get("enable_tcp", True)
    udp_port: int = int(params.get("udp_port", 5514))
    tcp_port: int = int(params.get("tcp_port", 5514))
    max_bytes: int = int(params.get("max_bytes", 8192))

    result: dict[str, Any] = {"udp_transport": None, "tcp_server": None}

    if enable_udp:
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: SyslogUDPProtocol(on_message, max_bytes),
                local_addr=("0.0.0.0", udp_port),
            )
            result["udp_transport"] = transport
            logger.info("Syslog UDP listener started on port %d", udp_port)
        except OSError as exc:
            logger.error("Failed to start UDP syslog listener on port %d: %s", udp_port, exc)

    if enable_tcp:
        try:

            async def client_handler(
                reader: asyncio.StreamReader,
                writer: asyncio.StreamWriter,
            ) -> None:
                await _handle_tcp_client(reader, writer, on_message, max_bytes)

            server = await asyncio.start_server(client_handler, "0.0.0.0", tcp_port)
            result["tcp_server"] = server
            logger.info("Syslog TCP listener started on port %d", tcp_port)
        except OSError as exc:
            logger.error("Failed to start TCP syslog listener on port %d: %s", tcp_port, exc)

    return result


async def stop_syslog_listeners(listeners: dict[str, Any]) -> None:
    """Stop syslog listeners.

    Args:
        listeners: Dict returned from start_syslog_listeners.
    """
    udp_transport = listeners.get("udp_transport")
    if udp_transport:
        udp_transport.close()
        logger.info("Stopped syslog UDP listener")

    tcp_server = listeners.get("tcp_server")
    if tcp_server:
        tcp_server.close()
        await tcp_server.wait_closed()
        logger.info("Stopped syslog TCP listener")
