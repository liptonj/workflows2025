"""File system watcher for monitoring .bin file additions."""

import logging
from collections.abc import Callable
from pathlib import Path

from watchdog.events import (
    DirCreatedEvent,
    DirMovedEvent,
    FileCreatedEvent,
    FileMovedEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

logger = logging.getLogger(__name__)


class BinFileHandler(FileSystemEventHandler):
    """Handler for .bin file system events."""

    def __init__(self, on_file_added: Callable[[Path], None] | None = None) -> None:
        """Initialize handler with optional callback.

        Args:
            on_file_added: Callback function when a .bin file is added.
        """
        super().__init__()
        self.on_file_added = on_file_added

    def _is_bin_file(self, path: str | bytes) -> bool:
        """Check if the file has a .bin extension.

        Args:
            path: File path to check.

        Returns:
            True if file has .bin extension.
        """
        if isinstance(path, bytes):
            return path.lower().endswith(b".bin")
        return path.lower().endswith(".bin")

    def _handle_new_bin_file(self, file_path: str | bytes) -> None:
        """Process a newly added .bin file.

        Args:
            file_path: Path to the new .bin file.
        """
        if not self._is_bin_file(file_path):
            return

        # Convert bytes to str if needed
        path_str = file_path.decode() if isinstance(file_path, bytes) else file_path
        path = Path(path_str)
        logger.info("New .bin file detected: %s", path.name)

        if self.on_file_added:
            self.on_file_added(path)

    def on_created(self, event: DirCreatedEvent | FileCreatedEvent) -> None:
        """Handle file creation events.

        Args:
            event: File system event.
        """
        if event.is_directory:
            return
        self._handle_new_bin_file(event.src_path)

    def on_moved(self, event: DirMovedEvent | FileMovedEvent) -> None:
        """Handle file move events (includes renames).

        Args:
            event: File system event.
        """
        if event.is_directory:
            return
        self._handle_new_bin_file(event.dest_path)


class BinFileWatcher:
    """Watches a directory for .bin file additions."""

    def __init__(
        self,
        watch_directory: Path,
        on_file_added: Callable[[Path], None] | None = None,
    ) -> None:
        """Initialize the file watcher.

        Args:
            watch_directory: Directory to monitor for .bin files.
            on_file_added: Callback when new .bin file is detected.
        """
        self.watch_directory = watch_directory
        self.handler = BinFileHandler(on_file_added=on_file_added)
        self.observer = Observer()
        self._is_running = False

    def start(self) -> None:
        """Start watching the directory."""
        if self._is_running:
            logger.warning("Watcher is already running")
            return

        if not self.watch_directory.exists():
            logger.error("Watch directory does not exist: %s", self.watch_directory)
            raise FileNotFoundError(f"Directory not found: {self.watch_directory}")

        self.observer.schedule(
            self.handler,
            str(self.watch_directory),
            recursive=False,
        )
        self.observer.start()
        self._is_running = True
        logger.info("Started watching directory: %s", self.watch_directory)

    def stop(self) -> None:
        """Stop watching the directory."""
        if not self._is_running:
            return

        self.observer.stop()
        self.observer.join(timeout=5)
        self._is_running = False
        logger.info("Stopped watching directory")

    @property
    def is_running(self) -> bool:
        """Check if watcher is currently running."""
        return self._is_running
