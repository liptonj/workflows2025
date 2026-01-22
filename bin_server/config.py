"""Configuration settings for the bin file server."""

import os
from pathlib import Path

# Server configuration
HOST: str = os.getenv("BIN_SERVER_HOST", "0.0.0.0")
PORT: int = int(os.getenv("BIN_SERVER_PORT", "80"))

# Directory to watch and serve files from
BIN_DIRECTORY: Path = Path(os.getenv("BIN_SERVER_DIRECTORY", ".")).resolve()

# Logging configuration
LOG_LEVEL: str = os.getenv("BIN_SERVER_LOG_LEVEL", "INFO")
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
