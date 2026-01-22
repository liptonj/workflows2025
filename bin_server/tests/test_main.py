"""Unit tests for the bin file server."""

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
    with patch("config.BIN_DIRECTORY", temp_bin_directory):
        with patch("main.config.BIN_DIRECTORY", temp_bin_directory):
            # Import after patching to get correct config
            from main import app, available_files
            available_files.clear()
            available_files[sample_bin_file.name] = sample_bin_file
            
            with TestClient(app) as test_client:
                yield test_client


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
        """List files should return available .bin files."""
        response = client.get("/files")
        
        assert response.status_code == 200
        data = response.json()
        assert "files" in data
        assert "test_firmware.bin" in data["files"]

    def test_list_files_returns_sorted_list(
        self, client: TestClient, temp_bin_directory: Path
    ) -> None:
        """Files should be returned in sorted order."""
        # Create additional files
        from main import available_files
        
        for name in ["zebra.bin", "alpha.bin", "beta.bin"]:
            file_path = temp_bin_directory / name
            file_path.write_bytes(b"\x00")
            available_files[name] = file_path
        
        response = client.get("/files")
        data = response.json()
        
        assert data["files"] == sorted(data["files"])


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
        from file_watcher import BinFileHandler
        
        handler = BinFileHandler()
        
        assert handler._is_bin_file("firmware.bin") is True
        assert handler._is_bin_file("FIRMWARE.BIN") is True
        assert handler._is_bin_file("test.Bin") is True
        assert handler._is_bin_file("script.py") is False
        assert handler._is_bin_file("image.png") is False

    def test_watcher_callback_invoked(self, temp_bin_directory: Path) -> None:
        """Callback should be invoked when .bin file is detected."""
        from file_watcher import BinFileHandler
        from watchdog.events import FileCreatedEvent
        
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
        from file_watcher import BinFileHandler
        from watchdog.events import FileCreatedEvent
        
        detected_files = []
        
        def callback(path: Path) -> None:
            detected_files.append(path)
        
        handler = BinFileHandler(on_file_added=callback)
        event = FileCreatedEvent(str(temp_bin_directory / "script.py"))
        handler.on_created(event)
        
        assert len(detected_files) == 0

    def test_watcher_start_stop(self, temp_bin_directory: Path) -> None:
        """Watcher should start and stop correctly."""
        from file_watcher import BinFileWatcher
        
        watcher = BinFileWatcher(watch_directory=temp_bin_directory)
        
        assert watcher.is_running is False
        
        watcher.start()
        assert watcher.is_running is True
        
        watcher.stop()
        assert watcher.is_running is False

    def test_watcher_raises_on_missing_directory(self) -> None:
        """Watcher should raise error for non-existent directory."""
        from file_watcher import BinFileWatcher
        
        watcher = BinFileWatcher(watch_directory=Path("/nonexistent/path"))
        
        with pytest.raises(FileNotFoundError):
            watcher.start()
