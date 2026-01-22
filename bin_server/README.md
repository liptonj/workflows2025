# Bin File Server

A FastAPI-based web server that automatically serves `.bin` files from a configured directory. The server watches for new files and immediately makes them available for download.

## Features

- Automatic detection of new `.bin` files
- RESTful API for listing and downloading files
- Runs as a Linux systemd service
- Security hardening with path traversal protection
- Comprehensive logging

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/files` | GET | List available `.bin` files |
| `/files/{filename}` | GET | Download a specific file |

## Quick Start

### Local Development

```bash
# Create virtual environment at project root using uv
cd /path/to/workflows2025
uv venv .venv
source .venv/bin/activate

# Install dependencies (including dev dependencies)
cd bin_server
uv pip install -e ".[dev]"

# Run the server
python main.py
```

### Production Installation (Linux)

```bash
# Prerequisites (Debian/Ubuntu)
sudo apt install python3 python3-venv

# Clone or copy files to the server
sudo ./install.sh

# Start the service
sudo systemctl start bin_server

# Enable on boot
sudo systemctl enable bin_server
```

## Configuration

Configuration is done via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `BIN_SERVER_HOST` | `0.0.0.0` | Host to bind to |
| `BIN_SERVER_PORT` | `80` | Port to listen on |
| `BIN_SERVER_DIRECTORY` | `.` (current dir) | Directory to serve files from |
| `BIN_SERVER_LOG_LEVEL` | `INFO` | Logging level |

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

### Health check

```bash
curl http://localhost/health
```

## Running Tests

```bash
# From project root with .venv activated
cd bin_server

# Run unit tests
pytest tests/ -v

# Run type checking
mypy *.py

# Run linter
ruff check .
```

## Adding Files

Use the helper script to add .bin files with correct permissions:

```bash
# Add a single file
sudo /opt/bin_server/add_file.sh firmware.bin

# Add multiple files
sudo /opt/bin_server/add_file.sh *.bin
```

The script will:
- Move the file to `/opt/bin_server/files/`
- Set ownership to `binserver:binserver`
- Set permissions to 644 (read-only)

## Service Management

```bash
# Start service
sudo systemctl start bin_server

# Stop service
sudo systemctl stop bin_server

# Restart service
sudo systemctl restart bin_server

# View status
sudo systemctl status bin_server

# View logs
sudo journalctl -u bin_server -f
```

## Security Notes

- Only `.bin` files are served
- Path traversal attacks are blocked
- Service runs as dedicated non-root user (`binserver`)
- Systemd security hardening is enabled
- Files directory has restricted write access

## File Structure

```
/opt/bin_server/
├── main.py           # FastAPI application
├── config.py         # Configuration
├── file_watcher.py   # Directory monitoring
├── pyproject.toml    # Python dependencies and project config
├── venv/             # Virtual environment
└── files/            # Directory for .bin files
```
