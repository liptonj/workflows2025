#!/bin/bash
# Script to add .bin files to the bin_server with correct permissions
set -e

FILES_DIR="/opt/bin_server/files"
SERVICE_USER="binserver"
SERVICE_GROUP="binserver"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

usage() {
    echo "Usage: $0 <file.bin> [file2.bin] ..."
    echo ""
    echo "Moves .bin files to ${FILES_DIR} with correct permissions."
    echo "Files will be owned by ${SERVICE_USER}:${SERVICE_GROUP}"
    echo ""
    echo "Examples:"
    echo "  $0 firmware.bin"
    echo "  $0 *.bin"
    exit 1
}

# Check for arguments
if [[ $# -eq 0 ]]; then
    usage
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if files directory exists
if [[ ! -d "${FILES_DIR}" ]]; then
    echo -e "${RED}Error: Files directory does not exist: ${FILES_DIR}${NC}"
    echo "Have you run install.sh first?"
    exit 1
fi

# Process each file
SUCCESS_COUNT=0
FAIL_COUNT=0

for FILE in "$@"; do
    # Check if file exists
    if [[ ! -f "${FILE}" ]]; then
        echo -e "${RED}Skipping: ${FILE} (not found)${NC}"
        ((FAIL_COUNT++))
        continue
    fi

    # Check if it's a .bin file
    if [[ ! "${FILE}" =~ \.bin$ ]]; then
        echo -e "${RED}Skipping: ${FILE} (not a .bin file)${NC}"
        ((FAIL_COUNT++))
        continue
    fi

    FILENAME=$(basename "${FILE}")
    DEST="${FILES_DIR}/${FILENAME}"

    # Check if file already exists in destination
    if [[ -f "${DEST}" ]]; then
        echo -e "${RED}Skipping: ${FILENAME} (already exists in ${FILES_DIR})${NC}"
        echo "  Use: sudo rm ${DEST} to remove first"
        ((FAIL_COUNT++))
        continue
    fi

    # Move file
    mv "${FILE}" "${DEST}"

    # Set ownership and permissions
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${DEST}"
    chmod 644 "${DEST}"

    echo -e "${GREEN}Added: ${FILENAME}${NC}"
    ((SUCCESS_COUNT++))
done

echo ""
echo "=== Summary ==="
echo -e "Added: ${GREEN}${SUCCESS_COUNT}${NC} file(s)"
if [[ ${FAIL_COUNT} -gt 0 ]]; then
    echo -e "Skipped: ${RED}${FAIL_COUNT}${NC} file(s)"
fi

# Show current files
echo ""
echo "Files in ${FILES_DIR}:"
ls -la "${FILES_DIR}"/*.bin 2>/dev/null || echo "  (no .bin files)"
