"""Unit tests for the fwserve file server."""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def temp_bin_directory():
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_bin_file(temp_bin_directory: Path) -> Path:
    """Create a sample .bin file for testing."""
    bin_file = temp_bin_directory / "test_firmware.bin"
    bin_file.write_bytes(b"\x00\x01\x02\x03\x04\x05")
    return bin_file


@pytest.fixture
def client(temp_bin_directory: Path, sample_bin_file: Path):
    """Create test client with mocked configuration."""
    with patch("fwserve.config.BIN_DIRECTORY", temp_bin_directory):
        with (
            patch("fwserve.config.SYSLOG_ENABLE_UDP", False),
            patch("fwserve.config.SYSLOG_ENABLE_TCP", False),
            patch("fwserve.config.SYSLOG_LOG_FILE", temp_bin_directory / "syslog.log"),
            patch("fwserve.config.SYSLOG_TAIL_SIZE", 10),
            patch("fwserve.config.SYSLOG_HISTORY_LIMIT", 10),
            patch("fwserve.config.BIN_UPLOAD_MAX_BYTES", 1024 * 1024),
            patch("fwserve.app.config.BIN_DIRECTORY", temp_bin_directory),
            patch("fwserve.app.config.SYSLOG_ENABLE_UDP", False),
            patch("fwserve.app.config.SYSLOG_ENABLE_TCP", False),
            patch("fwserve.app.config.SYSLOG_LOG_FILE", temp_bin_directory / "syslog.log"),
            patch("fwserve.app.config.SYSLOG_TAIL_SIZE", 10),
            patch("fwserve.app.config.SYSLOG_HISTORY_LIMIT", 10),
            patch("fwserve.app.config.BIN_UPLOAD_MAX_BYTES", 1024 * 1024),
        ):
            # Import after patching to get correct config
            from fwserve.app import app, available_files

            available_files.clear()
            available_files[sample_bin_file.name] = sample_bin_file

            with TestClient(app) as test_client:
                yield test_client


class TestIndexEndpoint:
    """Tests for the landing page endpoint."""

    def test_index_returns_html(self, client: TestClient) -> None:
        """Index should return HTML landing page."""
        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "FWServe" in response.text
        assert "/upload" in response.text
        assert "/syslog" in response.text
        assert "/files" in response.text


class TestHealthEndpoint:
    """Tests for the health check endpoint."""

    def test_health_check_returns_healthy(self, client: TestClient) -> None:
        """Health endpoint should return healthy status."""
        response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}


class TestListFilesEndpoint:
    """Tests for the file listing endpoint."""

    def test_list_files_returns_available_files(self, client: TestClient) -> None:
        """List files should return available .bin files with metadata."""
        response = client.get("/files")

        assert response.status_code == 200
        data = response.json()
        assert "files" in data
        # Files are now returned as dicts with name, size, md5
        file_names = [f["name"] for f in data["files"]]
        assert "test_firmware.bin" in file_names
        # Verify structure of file entry
        test_file = next(f for f in data["files"] if f["name"] == "test_firmware.bin")
        assert "size" in test_file
        assert "md5" in test_file

    def test_list_files_returns_sorted_list(
        self, client: TestClient, temp_bin_directory: Path
    ) -> None:
        """Files should be returned in sorted order by name."""
        # Create additional files
        from fwserve.app import available_files

        for name in ["zebra.bin", "alpha.bin", "beta.bin"]:
            file_path = temp_bin_directory / name
            file_path.write_bytes(b"\x00")
            available_files[name] = file_path

        response = client.get("/files")
        data = response.json()

        # Extract names and verify sorted order
        file_names = [f["name"] for f in data["files"]]
        assert file_names == sorted(file_names)


class TestDownloadFileEndpoint:
    """Tests for the file download endpoint."""

    def test_download_existing_file(self, client: TestClient) -> None:
        """Should successfully download an existing .bin file."""
        response = client.get("/files/test_firmware.bin")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"
        assert response.content == b"\x00\x01\x02\x03\x04\x05"

    def test_download_nonexistent_file_returns_404(self, client: TestClient) -> None:
        """Should return 404 for non-existent files."""
        response = client.get("/files/nonexistent.bin")

        assert response.status_code == 404
        assert response.json()["detail"] == "File not found"

    def test_path_traversal_blocked(self, client: TestClient) -> None:
        """Should block path traversal attempts."""
        malicious_paths = [
            "../etc/passwd.bin",
            "..%2F..%2Fetc%2Fpasswd.bin",
            "test/../../secret.bin",
        ]

        for path in malicious_paths:
            response = client.get(f"/files/{path}")
            assert response.status_code in [400, 404], f"Path {path} was not blocked"

    def test_non_bin_extension_rejected(self, client: TestClient) -> None:
        """Should reject requests for non-.bin files."""
        response = client.get("/files/malware.exe")

        assert response.status_code == 400
        assert "Only .bin files" in response.json()["detail"]


class TestFileWatcher:
    """Tests for the file watcher functionality."""

    def test_bin_file_handler_detects_bin_files(self) -> None:
        """Handler should correctly identify .bin files."""
        from fwserve.file_watcher import BinFileHandler

        handler = BinFileHandler()

        assert handler._is_bin_file("firmware.bin") is True
        assert handler._is_bin_file("FIRMWARE.BIN") is True
        assert handler._is_bin_file("test.Bin") is True
        assert handler._is_bin_file("script.py") is False
        assert handler._is_bin_file("image.png") is False

    def test_watcher_callback_invoked(self, temp_bin_directory: Path) -> None:
        """Callback should be invoked when .bin file is detected."""
        from watchdog.events import FileCreatedEvent

        from fwserve.file_watcher import BinFileHandler

        detected_files = []

        def callback(path: Path) -> None:
            detected_files.append(path)

        handler = BinFileHandler(on_file_added=callback)
        event = FileCreatedEvent(str(temp_bin_directory / "new_firmware.bin"))
        handler.on_created(event)

        assert len(detected_files) == 1
        assert detected_files[0].name == "new_firmware.bin"

    def test_watcher_ignores_non_bin_files(self, temp_bin_directory: Path) -> None:
        """Watcher should ignore non-.bin files."""
        from watchdog.events import FileCreatedEvent

        from fwserve.file_watcher import BinFileHandler

        detected_files = []

        def callback(path: Path) -> None:
            detected_files.append(path)

        handler = BinFileHandler(on_file_added=callback)
        event = FileCreatedEvent(str(temp_bin_directory / "script.py"))
        handler.on_created(event)

        assert len(detected_files) == 0

    def test_watcher_start_stop(self, temp_bin_directory: Path) -> None:
        """Watcher should start and stop correctly."""
        from fwserve.file_watcher import BinFileWatcher

        watcher = BinFileWatcher(watch_directory=temp_bin_directory)

        assert watcher.is_running is False

        watcher.start()
        assert watcher.is_running is True

        watcher.stop()
        assert watcher.is_running is False

    def test_watcher_raises_on_missing_directory(self) -> None:
        """Watcher should raise error for non-existent directory."""
        from fwserve.file_watcher import BinFileWatcher

        watcher = BinFileWatcher(watch_directory=Path("/nonexistent/path"))

        with pytest.raises(FileNotFoundError):
            watcher.start()


class TestUploadEndpoint:
    """Tests for the upload endpoint."""

    def test_upload_rejects_non_bin(self, client: TestClient) -> None:
        """Upload should reject non .bin files."""
        response = client.post(
            "/upload",
            files={"file": ("bad.txt", b"data", "text/plain")},
        )

        assert response.status_code == 400
        assert "Only .bin files" in response.json()["detail"]

    def test_upload_accepts_bin(self, client: TestClient, temp_bin_directory: Path) -> None:
        """Upload should store .bin files."""
        response = client.post(
            "/upload",
            files={"file": ("new_firmware.bin", b"\x01\x02", "application/octet-stream")},
        )

        assert response.status_code == 200
        assert response.json()["status"] == "uploaded"
        stored_path = temp_bin_directory / "new_firmware.bin"
        assert stored_path.exists()


class TestSyslogEndpoints:
    """Smoke tests for syslog endpoints."""

    def test_syslog_history_returns_entries(self, client: TestClient) -> None:
        """Syslog history should return stored entries."""
        import asyncio

        from fwserve.app import state
        from fwserve.syslog_store import append_syslog_entry

        entry = {"host": "test-host", "message": "hello", "severity": 6}
        asyncio.run(append_syslog_entry({"store": state["syslog_store"], "entry": entry}))

        response = client.get("/syslog/history")
        assert response.status_code == 200
        payload = response.json()
        assert payload["entries"]
