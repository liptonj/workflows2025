"""Configuration settings for the fwserve file server."""

import os
from pathlib import Path
from zoneinfo import ZoneInfo

# Server configuration
HOST: str = os.getenv("FWSERVE_HOST", "0.0.0.0")
PORT: int = int(os.getenv("FWSERVE_PORT", "8080"))

# Directory to watch and serve files from
BIN_DIRECTORY: Path = Path(os.getenv("FWSERVE_DIRECTORY", ".")).resolve()

# Upload configuration (default 10GB)
BIN_UPLOAD_MAX_BYTES: int = int(os.getenv("FWSERVE_UPLOAD_MAX_BYTES", "10737418240"))

# Syslog server configuration
SYSLOG_ENABLE_UDP: bool = os.getenv("SYSLOG_ENABLE_UDP", "true").lower() == "true"
SYSLOG_ENABLE_TCP: bool = os.getenv("SYSLOG_ENABLE_TCP", "true").lower() == "true"
SYSLOG_UDP_PORT: int = int(os.getenv("SYSLOG_UDP_PORT", "514"))
SYSLOG_TCP_PORT: int = int(os.getenv("SYSLOG_TCP_PORT", "514"))
SYSLOG_MAX_MESSAGE_BYTES: int = int(os.getenv("SYSLOG_MAX_MESSAGE_BYTES", "8192"))

# Syslog storage configuration
SYSLOG_LOG_FILE: Path = Path(
    os.getenv("SYSLOG_LOG_FILE", str(BIN_DIRECTORY / "syslog.log"))
).resolve()
SYSLOG_TAIL_SIZE: int = int(os.getenv("SYSLOG_TAIL_SIZE", "5000"))
SYSLOG_HISTORY_LIMIT: int = int(os.getenv("SYSLOG_HISTORY_LIMIT", "500"))

# Timezone configuration
TIMEZONE: ZoneInfo = ZoneInfo(os.getenv("FWSERVE_TIMEZONE", "America/New_York"))

# Logging configuration
LOG_LEVEL: str = os.getenv("FWSERVE_LOG_LEVEL", "INFO")
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
