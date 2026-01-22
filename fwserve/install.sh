#!/bin/bash
# Installation script for Bin File Server
set -e

INSTALL_DIR="/opt/bin_server"
FILES_DIR="${INSTALL_DIR}/files"
LOGS_DIR="${INSTALL_DIR}/logs"
SERVICE_NAME="bin_server"
SERVICE_USER="binserver"
SERVICE_GROUP="binserver"

echo "=== Bin File Server Installation ==="

# Detect if this is an update
IS_UPDATE=false
if [[ -d "${INSTALL_DIR}/venv" ]]; then
    IS_UPDATE=true
    echo "Detected existing installation - running update"
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (use sudo)"
   exit 1
fi

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    echo "  Install with: apt install python3"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "Found Python ${PYTHON_VERSION}"

# Check for python3-venv
if ! python3 -m venv --help &> /dev/null; then
    echo "Error: python3-venv is not installed"
    echo "  Install with: apt install python3-venv"
    echo "  Or for specific version: apt install python${PYTHON_VERSION}-venv"
    exit 1
fi

# Create dedicated service user and group
echo "Creating service user and group..."
if ! getent group "${SERVICE_GROUP}" > /dev/null 2>&1; then
    groupadd --system "${SERVICE_GROUP}"
    echo "  Created group: ${SERVICE_GROUP}"
else
    echo "  Group ${SERVICE_GROUP} already exists"
fi

if ! getent passwd "${SERVICE_USER}" > /dev/null 2>&1; then
    useradd --system \
        --gid "${SERVICE_GROUP}" \
        --home-dir "${INSTALL_DIR}" \
        --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "Bin File Server" \
        "${SERVICE_USER}"
    echo "  Created user: ${SERVICE_USER}"
else
    echo "  User ${SERVICE_USER} already exists"
fi

# Stop service if updating
if [[ "${IS_UPDATE}" == true ]]; then
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "Stopping service for update..."
        systemctl stop "${SERVICE_NAME}"
    fi
fi

# Create installation directory
echo "Creating installation directories..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${FILES_DIR}"
mkdir -p "${LOGS_DIR}"

# Copy application files
echo "Copying application files..."
cp main.py "${INSTALL_DIR}/"
cp config.py "${INSTALL_DIR}/"
cp file_watcher.py "${INSTALL_DIR}/"
cp syslog_parser.py "${INSTALL_DIR}/"
cp syslog_store.py "${INSTALL_DIR}/"
cp syslog_server.py "${INSTALL_DIR}/"
cp pyproject.toml "${INSTALL_DIR}/"
cp README.md "${INSTALL_DIR}/"
cp add_file.sh "${INSTALL_DIR}/"

# Create or update virtual environment
if [[ "${IS_UPDATE}" == true ]]; then
    echo "Updating virtual environment..."
    python3 -m venv --upgrade "${INSTALL_DIR}/venv"
else
    echo "Creating virtual environment..."
    python3 -m venv "${INSTALL_DIR}/venv"
fi

# Install/update dependencies
echo "Installing dependencies..."
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install --upgrade "${INSTALL_DIR}/"

# Set ownership and permissions
echo "Setting permissions..."
# Application files owned by root (read-only for security)
chown -R root:root "${INSTALL_DIR}"
chmod 755 "${INSTALL_DIR}"
chmod 644 "${INSTALL_DIR}"/*.py
chmod 644 "${INSTALL_DIR}"/pyproject.toml
chmod 644 "${INSTALL_DIR}"/README.md
chmod 755 "${INSTALL_DIR}"/add_file.sh

# Venv needs to be executable
chmod -R 755 "${INSTALL_DIR}/venv"

# Files directory owned by service user (for file watching and uploads)
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${FILES_DIR}"
chmod 755 "${FILES_DIR}"

# Logs directory owned by service user (for syslog storage)
chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "${LOGS_DIR}"
chmod 755 "${LOGS_DIR}"

# Install systemd service
echo "Installing systemd service..."
cp bin_server.service "/etc/systemd/system/${SERVICE_NAME}.service"
systemctl daemon-reload

# Restart service if this was an update
if [[ "${IS_UPDATE}" == true ]]; then
    echo "Restarting service..."
    systemctl start "${SERVICE_NAME}"
fi

echo ""
if [[ "${IS_UPDATE}" == true ]]; then
    echo "=== Update Complete ==="
else
    echo "=== Installation Complete ==="
fi
echo ""
echo "To start the service:"
echo "  sudo systemctl start ${SERVICE_NAME}"
echo ""
echo "To enable on boot:"
echo "  sudo systemctl enable ${SERVICE_NAME}"
echo ""
echo "To check status:"
echo "  sudo systemctl status ${SERVICE_NAME}"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "To add .bin files:"
echo "  sudo ${INSTALL_DIR}/add_file.sh /path/to/firmware.bin"
echo ""
echo "Or manually place files in: ${FILES_DIR}"
echo ""
echo "Server endpoints:"
echo "  Files API:     http://localhost/files"
echo "  Upload UI:     http://localhost/upload"
echo "  Syslog UI:     http://localhost/syslog"
echo ""
echo "Syslog server listening on UDP/TCP ports (default 514)"
echo "Configure via environment variables in systemd unit file"
echo ""
