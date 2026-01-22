# FWServe

A FastAPI-based firmware file server that automatically serves `.bin` files from a configured directory, with a web upload UI and integrated syslog receiver.

## Features

- Automatic detection of new `.bin` files
- RESTful API for listing and downloading files
- Web UI for uploading `.bin` files
- Integrated syslog server (UDP + TCP)
- Real-time syslog viewer with filtering
- CLI for easy installation as a systemd service
- Runs as a Linux systemd service

## Installation

### From PyPI

```bash
pip install fwserve
```

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/fwserve.git
cd fwserve

# Install with pip
pip install .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

### Run in Development Mode

```bash
# Run with default settings (port 8080, current directory)
fwserve run

# Run with custom settings
fwserve run --port 8080 --directory /path/to/files --reload
```

### Install as a Service (Linux)

```bash
# Install with default settings (requires root)
sudo fwserve install

# Install with custom settings
sudo fwserve install --port 80 --syslog-port 514

# Check service status
fwserve status

# Uninstall the service
sudo fwserve uninstall
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/files` | GET | List available `.bin` files |
| `/files/{filename}` | GET | Download a specific file |
| `/upload` | GET | Upload form UI |
| `/upload` | POST | Upload a `.bin` file |
| `/syslog` | GET | Real-time syslog viewer UI |
| `/syslog/history` | GET | Get recent syslog entries |
| `/syslog/stream` | GET | SSE stream of syslog entries |

## CLI Commands

```bash
# Show help
fwserve --help

# Run the server
fwserve run --host 0.0.0.0 --port 8080 --directory ./files

# Install as systemd service (requires root)
sudo fwserve install --port 80 --syslog-port 514

# Check service status
fwserve status

# Uninstall service (requires root)
sudo fwserve uninstall
```

## Configuration

Configuration is done via environment variables:

### Server Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FWSERVE_HOST` | `0.0.0.0` | Host to bind to |
| `FWSERVE_PORT` | `8080` | HTTP port to listen on |
| `FWSERVE_DIRECTORY` | `.` | Directory to serve files from |
| `FWSERVE_LOG_LEVEL` | `INFO` | Logging level |
| `FWSERVE_TIMEZONE` | `America/New_York` | Timezone for timestamps |

### Upload Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FWSERVE_UPLOAD_MAX_BYTES` | `104857600` | Maximum upload size (100MB) |

### Syslog Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `SYSLOG_ENABLE_UDP` | `true` | Enable UDP syslog listener |
| `SYSLOG_ENABLE_TCP` | `true` | Enable TCP syslog listener |
| `SYSLOG_UDP_PORT` | `5514` | UDP port for syslog |
| `SYSLOG_TCP_PORT` | `5514` | TCP port for syslog |
| `SYSLOG_LOG_FILE` | `<directory>/syslog.log` | Path to syslog storage file |
| `SYSLOG_TAIL_SIZE` | `5000` | Number of entries to keep in memory |
| `SYSLOG_HISTORY_LIMIT` | `500` | Max entries returned by history endpoint |

## Usage Examples

### List available files

```bash
curl http://localhost:8080/files
```

Response:
```json
{
  "files": ["firmware_v1.0.bin", "update_v2.1.bin"]
}
```

### Download a file

```bash
curl -O http://localhost:8080/files/firmware_v1.0.bin
```

### Upload a file

```bash
curl -X POST -F "file=@firmware.bin" http://localhost:8080/upload
```

### Send syslog messages

```bash
# UDP
echo "<14>Test message from host1" | nc -u localhost 5514

# TCP
echo "<14>Test message from host1" | nc localhost 5514
```

### Get syslog history with filters

```bash
# Get all entries
curl http://localhost:8080/syslog/history

# Filter by host
curl "http://localhost:8080/syslog/history?host=router1"

# Filter by severity and message
curl "http://localhost:8080/syslog/history?severity=err&q=failed"
```

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run type checking
mypy src/fwserve/

# Run linter
ruff check src/
```

## Building the Package

```bash
# Install build dependencies
pip install build

# Build wheel and sdist
python -m build

# The built packages will be in dist/
ls dist/
# fwserve-1.0.0-py3-none-any.whl
# fwserve-1.0.0.tar.gz
```

## Service Management

After installing with `fwserve install`:

```bash
# Start service
sudo systemctl start fwserve

# Stop service
sudo systemctl stop fwserve

# Restart service
sudo systemctl restart fwserve

# View status
sudo systemctl status fwserve

# View logs
sudo journalctl -u fwserve -f
```

## Security Notes

- Only `.bin` files are served/uploaded
- Path traversal attacks are blocked
- Service runs as dedicated non-root user (`fwserve`)
- Systemd security hardening is enabled
- Files directory has restricted write access

## Project Structure

```
fwserve/
├── pyproject.toml       # Package configuration
├── README.md
├── src/
│   └── fwserve/
│       ├── __init__.py
│       ├── app.py           # FastAPI application
│       ├── cli.py           # Click CLI
│       ├── config.py        # Configuration
│       ├── file_watcher.py  # Directory monitoring
│       ├── syslog_parser.py # Syslog message parsing
│       ├── syslog_server.py # UDP/TCP listeners
│       └── syslog_store.py  # File-backed storage
└── tests/
    ├── test_main.py
    └── test_syslog.py
```
