"""FWServe - FastAPI firmware file server with syslog receiver."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("fwserve")
except PackageNotFoundError:
    __version__ = "0.0.0-dev"
