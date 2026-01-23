"""FastAPI web server for serving .bin files with automatic detection."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse

from fwserve import config
from fwserve.file_watcher import BinFileWatcher
from fwserve.syslog_parser import parse_syslog_message
from fwserve.syslog_server import start_syslog_listeners, stop_syslog_listeners
from fwserve.syslog_store import append_syslog_entry, create_syslog_store, get_syslog_tail

if TYPE_CHECKING:
    pass

# Configure logging
logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)

# Template directory
TEMPLATES_DIR = Path(__file__).parent / "templates"


def _load_template(name: str) -> str:
    """Load an HTML template from the templates directory."""
    template_path = TEMPLATES_DIR / name
    return template_path.read_text(encoding="utf-8")


# Track available .bin files
available_files: dict[str, Path] = {}

# File metadata (MD5 hashes, etc.)
file_metadata: dict[str, dict[str, str]] = {}
METADATA_FILE = config.BIN_DIRECTORY / ".file_metadata.json"

# Shared state
state: dict[str, Any] = {
    "watcher": None,
    "syslog_store": None,
    "syslog_listeners": None,
}
syslog_subscribers: set[asyncio.Queue[dict[str, object]]] = set()


def load_metadata() -> None:
    """Load file metadata from disk."""
    global file_metadata  # noqa: PLW0603
    if METADATA_FILE.exists():
        try:
            with METADATA_FILE.open("r") as f:
                file_metadata = json.load(f)
            logger.info("Loaded metadata for %d files", len(file_metadata))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to load metadata: %s", exc)
            file_metadata = {}
    else:
        file_metadata = {}


def save_metadata() -> None:
    """Save file metadata to disk."""
    try:
        with METADATA_FILE.open("w") as f:
            json.dump(file_metadata, f, indent=2)
    except OSError as exc:
        logger.error("Failed to save metadata: %s", exc)


def scan_existing_files() -> None:
    """Scan directory for existing .bin files on startup."""
    logger.info("Scanning for existing .bin files in: %s", config.BIN_DIRECTORY)

    # Load metadata first
    load_metadata()

    for file_path in config.BIN_DIRECTORY.glob("*.bin"):
        if file_path.is_file():
            available_files[file_path.name] = file_path
            logger.info("Found existing file: %s", file_path.name)

    # Clean up metadata for files that no longer exist
    orphaned = [name for name in file_metadata if name not in available_files]
    for name in orphaned:
        del file_metadata[name]
    if orphaned:
        save_metadata()
        logger.info("Cleaned up metadata for %d removed files", len(orphaned))

    logger.info("Found %d existing .bin files", len(available_files))


def on_new_file_detected(file_path: Path) -> None:
    """Callback when a new .bin file is detected.

    Args:
        file_path: Path to the newly detected file.
    """
    available_files[file_path.name] = file_path
    logger.info("Added new file to serve: %s", file_path.name)


def _sanitize_filename(filename: str) -> str:
    return filename.strip()


def _is_safe_filename(filename: str) -> bool:
    return ".." not in filename and "/" not in filename and "\\" not in filename


def _entry_matches_filters(entry: dict[str, object], filters: dict[str, str]) -> bool:
    host_filter = filters.get("host", "").strip().lower()
    severity_filter = filters.get("severity", "").strip().lower()
    message_filter = filters.get("q", "").strip().lower()

    if host_filter and host_filter not in str(entry.get("host", "")).lower():
        return False

    if severity_filter:
        severity_label = str(entry.get("severity_label") or "").lower()
        severity_value = entry.get("severity")
        if severity_filter != severity_label and severity_filter != str(severity_value):
            return False

    if message_filter and message_filter not in str(entry.get("message", "")).lower():
        return False

    return True


async def _broadcast_syslog_entry(entry: dict[str, object]) -> None:
    for queue in list(syslog_subscribers):
        try:
            queue.put_nowait(entry)
        except asyncio.QueueFull:
            logger.warning("Dropping syslog message for slow subscriber")


async def _handle_syslog_message(payload: dict[str, object]) -> None:
    syslog_store = state.get("syslog_store")
    if not syslog_store:
        return

    parsed = parse_syslog_message({
        "raw": payload.get("raw", ""),
        "source": payload.get("source", "unknown"),
    })
    
    # Skip filtered messages
    if parsed is None:
        return

    result = await append_syslog_entry({"store": syslog_store, "entry": parsed})
    if not result.get("is_success"):
        logger.error("Failed to store syslog message")
        return

    await _broadcast_syslog_entry(parsed)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown.

    Args:
        _app: FastAPI application instance (unused but required by lifespan protocol).

    Yields:
        None during application runtime.
    """
    # Startup
    logger.info("Starting fwserve file server...")
    logger.info("Serving files from: %s", config.BIN_DIRECTORY)

    # Ensure directory exists
    if not config.BIN_DIRECTORY.exists():
        config.BIN_DIRECTORY.mkdir(parents=True, exist_ok=True)
        logger.info("Created bin directory: %s", config.BIN_DIRECTORY)

    # Scan for existing files
    scan_existing_files()

    # Start file watcher
    watcher = BinFileWatcher(
        watch_directory=config.BIN_DIRECTORY,
        on_file_added=on_new_file_detected,
    )
    watcher.start()
    state["watcher"] = watcher

    # Initialize syslog storage
    syslog_store = create_syslog_store(
        {
            "file_path": config.SYSLOG_LOG_FILE,
            "tail_size": config.SYSLOG_TAIL_SIZE,
        }
    )["store"]
    state["syslog_store"] = syslog_store

    # Start syslog listeners
    syslog_listeners = await start_syslog_listeners(
        {
            "on_message": _handle_syslog_message,
            "enable_udp": config.SYSLOG_ENABLE_UDP,
            "enable_tcp": config.SYSLOG_ENABLE_TCP,
            "udp_port": config.SYSLOG_UDP_PORT,
            "tcp_port": config.SYSLOG_TCP_PORT,
            "max_bytes": config.SYSLOG_MAX_MESSAGE_BYTES,
        }
    )
    state["syslog_listeners"] = syslog_listeners

    yield

    # Shutdown
    logger.info("Shutting down fwserve file server...")
    watcher_instance: BinFileWatcher | None = state.get("watcher")
    if watcher_instance:
        watcher_instance.stop()

    syslog_listeners_state: dict[str, Any] | None = state.get("syslog_listeners")
    if syslog_listeners_state:
        await stop_syslog_listeners(syslog_listeners_state)


app = FastAPI(
    title="FWServe",
    description="Firmware file server with upload UI and syslog receiver",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
async def index() -> HTMLResponse:
    """Render the landing page with links to all features."""
    return HTMLResponse(content=_load_template("index.html"))


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint.

    Returns:
        Health status response.
    """
    return {"status": "healthy"}


@app.get("/files")
async def list_files() -> dict[str, list[dict[str, Any]]]:
    """List all available .bin files with metadata.

    Returns:
        List of files with name, size, and md5 hash.
    """
    # Refresh list by checking which files still exist
    files_to_remove = []
    file_list: list[dict[str, Any]] = []

    for filename, filepath in available_files.items():
        if filepath.exists():
            stat = filepath.stat()
            meta = file_metadata.get(filename, {})
            file_list.append(
                {
                    "name": filename,
                    "size": stat.st_size,
                    "md5": meta.get("md5", ""),
                }
            )
        else:
            files_to_remove.append(filename)
            logger.warning("File no longer exists: %s", filename)

    for filename in files_to_remove:
        del available_files[filename]
        if filename in file_metadata:
            del file_metadata[filename]
            save_metadata()

    # Sort by name
    file_list.sort(key=lambda f: f["name"])

    return {"files": file_list}


@app.get("/files/{filename}")
async def download_file(filename: str, request: Request) -> FileResponse:
    """Download a specific .bin file.

    Args:
        filename: Name of the file to download.
        request: FastAPI request object.

    Returns:
        File response for download.

    Raises:
        HTTPException: If file not found or invalid filename.
    """
    # Security: Prevent path traversal
    if ".." in filename or "/" in filename or "\\" in filename:
        logger.warning(
            "Rejected path traversal attempt: %s from %s",
            filename,
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=400, detail="Invalid filename")

    # Ensure .bin extension
    if not filename.lower().endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin files are served")

    file_path = available_files.get(filename)

    if not file_path:
        # Check if file exists but wasn't in our cache
        potential_path = config.BIN_DIRECTORY / filename
        if potential_path.exists() and potential_path.is_file():
            available_files[filename] = potential_path
            file_path = potential_path
            logger.info("Found uncached file: %s", filename)

    if not file_path or not file_path.exists():
        logger.info("File not found: %s", filename)
        raise HTTPException(status_code=404, detail="File not found")

    logger.info(
        "Serving file: %s to %s",
        filename,
        request.client.host if request.client else "unknown",
    )

    return FileResponse(
        path=file_path,
        filename=filename,
        media_type="application/octet-stream",
    )


@app.get("/upload")
async def upload_page() -> HTMLResponse:
    """Render the firmware files page with upload and file list."""
    return HTMLResponse(content=_load_template("upload.html"))


@app.post("/upload")
async def upload_file(
    file: Annotated[UploadFile, File()],
    md5: Annotated[str, Form()] = "",
) -> dict[str, str]:
    """Handle file upload and store the .bin file with optional MD5 hash."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    filename = _sanitize_filename(file.filename)
    if not _is_safe_filename(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    if not filename.lower().endswith(".bin"):
        raise HTTPException(status_code=400, detail="Only .bin files are allowed")

    destination = config.BIN_DIRECTORY / filename
    if destination.exists():
        raise HTTPException(status_code=409, detail="File already exists")

    # Validate MD5 format if provided
    md5_clean = md5.strip().lower()
    if md5_clean and len(md5_clean) != 32:
        raise HTTPException(status_code=400, detail="Invalid MD5 hash format")

    logger.info("Uploading file: %s", filename)
    size = 0
    try:
        with destination.open("wb") as file_handle:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > config.BIN_UPLOAD_MAX_BYTES:
                    raise HTTPException(status_code=413, detail="File too large")
                file_handle.write(chunk)
    except HTTPException:
        if destination.exists():
            destination.unlink()
        raise
    except OSError as exc:
        logger.error("Failed to write upload %s: %s", filename, exc)
        raise HTTPException(status_code=500, detail="Failed to store file") from exc
    finally:
        await file.close()

    if size == 0:
        destination.unlink(missing_ok=True)
        raise HTTPException(status_code=400, detail="Empty files are not allowed")

    available_files[filename] = destination

    # Store metadata if MD5 provided
    if md5_clean:
        file_metadata[filename] = {"md5": md5_clean}
        save_metadata()
        logger.info("Upload complete: %s (%d bytes, md5=%s)", filename, size, md5_clean)
    else:
        logger.info("Upload complete: %s (%d bytes)", filename, size)

    return {"status": "uploaded", "filename": filename, "md5": md5_clean}


@app.get("/syslog")
async def syslog_page() -> HTMLResponse:
    """Render the real-time syslog viewer page."""
    return HTMLResponse(content=_load_template("syslog.html"))


@app.get("/syslog/history")
async def syslog_history(
    host: str | None = None,
    severity: str | None = None,
    q: str | None = None,
) -> dict[str, list[dict[str, object]]]:
    """Get recent syslog entries with optional filtering."""
    syslog_store = state.get("syslog_store")
    if not syslog_store:
        return {"entries": []}

    filters = {"host": host or "", "severity": severity or "", "q": q or ""}
    result = get_syslog_tail(
        {
            "store": syslog_store,
            "limit": config.SYSLOG_HISTORY_LIMIT,
            "filters": filters,
        }
    )
    return {"entries": result["entries"]}


@app.get("/syslog/stream")
async def syslog_stream(
    host: str | None = None,
    severity: str | None = None,
    q: str | None = None,
) -> StreamingResponse:
    """Stream syslog entries in real-time via Server-Sent Events."""
    filters = {"host": host or "", "severity": severity or "", "q": q or ""}
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    syslog_subscribers.add(queue)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while True:
                entry = await queue.get()
                if not _entry_matches_filters(entry, filters):
                    continue
                data = json.dumps(entry, ensure_ascii=True)
                yield f"data: {data}\n\n"
        finally:
            syslog_subscribers.discard(queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions globally.

    Args:
        request: FastAPI request object.
        exc: Exception that was raised.

    Returns:
        JSON error response.
    """
    logger.exception("Unhandled exception for %s: %s", request.url, exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
