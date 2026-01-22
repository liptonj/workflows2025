# FWServe

A FastAPI-based firmware file server that automatically serves `.bin` files from a configured directory, with a web upload UI and integrated syslog receiver.

## Features

- Automatic detection of new `.bin` files
- RESTful API for listing and downloading files
- Web UI for uploading `.bin` files
- Integrated syslog server (UDP + TCP)
- Real-time syslog viewer with filtering
- CLI for easy installation as a systemd service
- Runs as a Linux systemd service with dedicated user

## Installation

### From PyPI (Recommended)

```bash
# Install using pipx (recommended for CLI tools)
pipx install fwserve

# Or install using pip
pip install fwserve
```

### From Source

```bash
# Clone the repository
git clone https://github.com/liptonj/workflows2025.git
cd workflows2025/fwserve

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

### Install as a Production Service (Linux)

The `install` command sets up everything needed to run fwserve as a systemd service:

1. Creates a dedicated `fwserve` user and group
2. Creates `/opt/fwserve` directory structure
3. Creates a Python virtual environment with fwserve installed
4. Installs and configures the systemd service

```bash
# Install with default settings (requires root)
# Uses port 80 for HTTP and port 514 for syslog (standard syslog port)
sudo ~/.local/bin/fwserve install

# Install with custom settings
sudo ~/.local/bin/fwserve install --port 8080 --syslog-port 1514

# Start the service
sudo systemctl start fwserve

# Enable on boot
sudo systemctl enable fwserve

# Check service status
fwserve status
```

### Upgrading

To upgrade an existing installation:

```bash
# Upgrade the CLI tool
pipx upgrade fwserve

# Reinstall the service (preserves data in files/ and logs/)
sudo ~/.local/bin/fwserve install --force

# Restart the service
sudo systemctl restart fwserve
```

### Uninstalling

```bash
# Uninstall the systemd service
sudo fwserve uninstall

# Optionally remove the data directory
sudo rm -rf /opt/fwserve
```

## Directory Structure After Install

```
/opt/fwserve/
├── venv/           # Python virtual environment with fwserve
├── files/          # Directory for .bin files (served/uploaded)
└── logs/
    └── syslog.log  # Persisted syslog messages
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Landing page with links to all features |
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

# Run the server (development)
fwserve run --host 0.0.0.0 --port 8080 --directory ./files

# Install as systemd service (requires root)
sudo fwserve install --port 80 --syslog-port 1514

# Check service status
fwserve status

# Uninstall service (requires root)
sudo fwserve uninstall
```

### Install Command Options

| Option | Default | Description |
|--------|---------|-------------|
| `--install-dir` | `/opt/fwserve` | Installation directory |
| `--user` | `fwserve` | Service user |
| `--group` | `fwserve` | Service group |
| `--port` | `80` | HTTP port |
| `--syslog-port` | `514` | Syslog UDP/TCP port (standard) |
| `--no-service` | `false` | Skip systemd service installation |
| `--force` | `false` | Force reinstall without prompts |

## Configuration

Configuration is done via environment variables (set in the systemd service file):

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
| `SYSLOG_UDP_PORT` | `514` | UDP port for syslog |
| `SYSLOG_TCP_PORT` | `514` | TCP port for syslog |
| `SYSLOG_LOG_FILE` | `<directory>/syslog.log` | Path to syslog storage file |
| `SYSLOG_TAIL_SIZE` | `5000` | Number of entries to keep in memory |
| `SYSLOG_HISTORY_LIMIT` | `500` | Max entries returned by history endpoint |

## Usage Examples

### List available files

```bash
curl http://localhost/files
```

Response:
```json
{
  "files": ["firmware_v1.0.bin", "update_v2.1.bin"]
}
```

### Download a file

```bash
curl -O http://localhost/files/firmware_v1.0.bin
```

### Upload a file

```bash
curl -X POST -F "file=@firmware.bin" http://localhost/upload
```

### Send syslog messages

```bash
# UDP
echo "<14>Test message from host1" | nc -u localhost 514

# TCP
echo "<14>Test message from host1" | nc localhost 514
```

### View syslog messages

Open `http://localhost/syslog` in a browser for the real-time viewer, or use the API:

```bash
# Get all entries
curl http://localhost/syslog/history

# Filter by host
curl "http://localhost/syslog/history?host=router1"

# Filter by severity and message
curl "http://localhost/syslog/history?severity=err&q=failed"
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

## Migration from Legacy Installation

If you previously installed using the old `install.sh` script, running `fwserve install` will:

1. Detect the legacy installation
2. Prompt for migration (or use `--force` to skip)
3. Remove old Python files (main.py, config.py, etc.)
4. Preserve your data directories (`files/` and `logs/`)
5. Install the new venv-based setup

## Security Notes

- Only `.bin` files are served/uploaded
- Path traversal attacks are blocked
- Service runs as dedicated non-root user (`fwserve`)
- Systemd security hardening is enabled (ProtectSystem, PrivateTmp, etc.)
- Files directory has restricted write access

## Troubleshooting

### Service fails to start

Check the logs:
```bash
sudo journalctl -u fwserve -n 50
```

### Permission denied errors

Ensure the fwserve user owns the directories:
```bash
sudo chown -R fwserve:fwserve /opt/fwserve/files /opt/fwserve/logs
```

### Port already in use

Check what's using the port:
```bash
sudo ss -tlnp | grep :80
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run type checking
mypy src/fwserve/

# Run linter
ruff check src/

# Format code
ruff format src/
```

## License

MIT
