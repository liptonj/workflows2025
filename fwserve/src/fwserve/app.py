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

    parsed = parse_syslog_message({"raw": payload.get("raw", "")})
    parsed["source"] = payload.get("source")

    result = await append_syslog_entry({"store": syslog_store, "entry": parsed})
    if not result.get("is_success"):
        logger.error("Failed to store syslog message")
        return

    await _broadcast_syslog_entry(parsed)


def _get_files_page_html() -> str:
    """Generate the HTML for the files page with upload and file list."""
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Firmware Files - FWServe</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      min-height: 100vh; color: #e0e0e0; padding: 20px;
    }
    .container { max-width: 1000px; margin: 0 auto; }
    header { margin-bottom: 30px; }
    h1 { color: #00d4ff; margin-bottom: 5px; }
    .subtitle { color: #888; }
    .back-link { color: #00d4ff; text-decoration: none; }
    .back-link:hover { text-decoration: underline; }

    .panel {
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 12px; padding: 25px; margin-bottom: 20px;
    }
    .panel h2 { color: #00d4ff; margin-bottom: 15px; font-size: 1.2rem; }

    .upload-form { display: flex; flex-direction: column; gap: 15px; }
    .form-row { display: flex; gap: 15px; flex-wrap: wrap; }
    .form-group { flex: 1; min-width: 200px; }
    .form-group label { display: block; margin-bottom: 5px; color: #aaa; }
    .form-group input {
      width: 100%; padding: 10px; border-radius: 6px;
      border: 1px solid rgba(255,255,255,0.2); background: rgba(0,0,0,0.3);
      color: #fff; font-size: 14px;
    }
    .form-group input[type="file"] { padding: 8px; }
    .form-group input::placeholder { color: #666; }

    .upload-btn {
      background: #00d4ff; color: #1a1a2e; padding: 12px 30px;
      border: none; border-radius: 6px; font-weight: 600;
      cursor: pointer; font-size: 16px; align-self: flex-start;
    }
    .upload-btn:hover { background: #00b8e6; }
    .upload-btn:disabled { background: #555; cursor: not-allowed; }

    .progress-container { display: none; margin-top: 15px; }
    .progress-bar {
      height: 24px; background: rgba(0,0,0,0.3); border-radius: 12px;
      overflow: hidden; position: relative;
    }
    .progress-fill {
      height: 100%; background: linear-gradient(90deg, #00d4ff, #00ff88);
      width: 0%; transition: width 0.2s;
    }
    .progress-text {
      position: absolute; top: 50%; left: 50%;
      transform: translate(-50%, -50%); font-size: 12px; font-weight: 600;
    }
    .upload-status { margin-top: 10px; font-size: 14px; }
    .status-success { color: #28a745; }
    .status-error { color: #dc3545; }

    .file-table { width: 100%; border-collapse: collapse; }
    .file-table th, .file-table td {
      text-align: left; padding: 12px;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    .file-table th { color: #00d4ff; font-weight: 600; }
    .file-table td { color: #ccc; }
    .file-table code {
      background: rgba(0,212,255,0.1); padding: 2px 6px;
      border-radius: 4px; font-family: monospace; font-size: 12px;
    }
    .file-table a { color: #00d4ff; text-decoration: none; }
    .file-table a:hover { text-decoration: underline; }
    .no-files { color: #888; font-style: italic; }

    .size { white-space: nowrap; }
    .md5 { font-family: monospace; font-size: 11px; color: #888; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <a href="/" class="back-link">&larr; Back to Home</a>
      <h1>Firmware Files</h1>
      <p class="subtitle">Upload and manage .bin firmware files</p>
    </header>

    <div class="panel">
      <h2>Upload New Firmware</h2>
      <form class="upload-form" id="uploadForm">
        <div class="form-row">
          <div class="form-group">
            <label for="file">Firmware File (.bin)</label>
            <input type="file" id="file" name="file" accept=".bin" required />
          </div>
          <div class="form-group">
            <label for="md5">MD5 Hash (optional)</label>
            <input type="text" id="md5" name="md5"
              placeholder="e.g. d41d8cd98f00b204e9800998ecf8427e"
              pattern="[a-fA-F0-9]{32}" maxlength="32" />
          </div>
        </div>
        <button type="submit" class="upload-btn" id="uploadBtn">Upload</button>
      </form>
      <div class="progress-container" id="progressContainer">
        <div class="progress-bar">
          <div class="progress-fill" id="progressFill"></div>
          <span class="progress-text" id="progressText">0%</span>
        </div>
        <div class="upload-status" id="uploadStatus"></div>
      </div>
    </div>

    <div class="panel">
      <h2>Available Files</h2>
      <div id="fileList"><p class="no-files">Loading...</p></div>
    </div>
  </div>

  <script>
    function formatSize(bytes) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    async function loadFiles() {
      try {
        const resp = await fetch('/files');
        const data = await resp.json();
        const container = document.getElementById('fileList');

        if (!data.files || data.files.length === 0) {
          container.innerHTML = '<p class="no-files">No files uploaded yet</p>';
          return;
        }

        let html = '<table class="file-table"><tr>';
        html += '<th>Filename</th><th>Size</th><th>MD5 Hash</th></tr>';
        for (const f of data.files) {
          html += '<tr>';
          html += '<td><a href="/files/' + f.name + '">' + f.name + '</a></td>';
          html += '<td class="size">' + formatSize(f.size) + '</td>';
          html += '<td class="md5">' + (f.md5 || '<em>Not provided</em>') + '</td>';
          html += '</tr>';
        }
        html += '</table>';
        container.innerHTML = html;
      } catch (e) {
        document.getElementById('fileList').innerHTML =
          '<p class="no-files">Error loading files</p>';
      }
    }

    document.getElementById('uploadForm').addEventListener('submit', function(e) {
      e.preventDefault();

      const fileInput = document.getElementById('file');
      const md5Input = document.getElementById('md5');
      const btn = document.getElementById('uploadBtn');
      const progress = document.getElementById('progressContainer');
      const fill = document.getElementById('progressFill');
      const text = document.getElementById('progressText');
      const status = document.getElementById('uploadStatus');

      if (!fileInput.files.length) return;

      const formData = new FormData();
      formData.append('file', fileInput.files[0]);
      formData.append('md5', md5Input.value.trim());

      btn.disabled = true;
      progress.style.display = 'block';
      status.textContent = '';
      status.className = 'upload-status';
      fill.style.width = '0%';
      text.textContent = '0%';

      const xhr = new XMLHttpRequest();

      xhr.upload.addEventListener('progress', function(e) {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          fill.style.width = pct + '%';
          text.textContent = pct + '% (' + formatSize(e.loaded) +
            ' / ' + formatSize(e.total) + ')';
        }
      });

      xhr.addEventListener('load', function() {
        btn.disabled = false;
        if (xhr.status === 200) {
          status.textContent = 'Upload complete!';
          status.className = 'upload-status status-success';
          fileInput.value = '';
          md5Input.value = '';
          loadFiles();
        } else {
          let msg = 'Upload failed';
          try {
            const err = JSON.parse(xhr.responseText);
            msg = err.detail || msg;
          } catch (e) {}
          status.textContent = msg;
          status.className = 'upload-status status-error';
        }
      });

      xhr.addEventListener('error', function() {
        btn.disabled = false;
        status.textContent = 'Network error';
        status.className = 'upload-status status-error';
      });

      xhr.open('POST', '/upload');
      xhr.send(formData);
    });

    loadFiles();
  </script>
</body>
</html>"""


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
    html = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>FWServe - Firmware File Server</title>
        <style>
          * { box-sizing: border-box; margin: 0; padding: 0; }
          body {
            font-family: system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            color: #e0e0e0;
          }
          .container {
            max-width: 900px;
            margin: 0 auto;
            padding: 40px 20px;
          }
          header {
            text-align: center;
            margin-bottom: 50px;
          }
          h1 {
            font-size: 2.5rem;
            color: #00d4ff;
            margin-bottom: 10px;
          }
          .subtitle {
            color: #888;
            font-size: 1.1rem;
          }
          .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
          }
          .card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 25px;
            transition: transform 0.2s, box-shadow 0.2s;
          }
          .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.2);
          }
          .card h2 {
            color: #00d4ff;
            font-size: 1.3rem;
            margin-bottom: 10px;
          }
          .card p {
            color: #aaa;
            margin-bottom: 15px;
            font-size: 0.95rem;
          }
          .card a {
            display: inline-block;
            background: #00d4ff;
            color: #1a1a2e;
            padding: 10px 20px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            transition: background 0.2s;
          }
          .card a:hover {
            background: #00b8e6;
          }
          .api-section {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 25px;
          }
          .api-section h2 {
            color: #00d4ff;
            margin-bottom: 20px;
          }
          .api-table {
            width: 100%;
            border-collapse: collapse;
          }
          .api-table th, .api-table td {
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
          }
          .api-table th {
            color: #00d4ff;
            font-weight: 600;
          }
          .api-table code {
            background: rgba(0, 212, 255, 0.1);
            padding: 3px 8px;
            border-radius: 4px;
            font-family: monospace;
          }
          .method {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
          }
          .method-get { background: #28a745; color: white; }
          .method-post { background: #007bff; color: white; }
          .status {
            margin-top: 30px;
            text-align: center;
            color: #666;
            font-size: 0.9rem;
          }
          .status-dot {
            display: inline-block;
            width: 10px;
            height: 10px;
            background: #28a745;
            border-radius: 50%;
            margin-right: 8px;
            animation: pulse 2s infinite;
          }
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
          }
        </style>
      </head>
      <body>
        <div class="container">
          <header>
            <h1>FWServe</h1>
            <p class="subtitle">Firmware File Server with Syslog Receiver</p>
          </header>

          <div class="cards">
            <div class="card">
              <h2>File Browser</h2>
              <p>View and download available .bin firmware files.</p>
              <a href="/files">Browse Files</a>
            </div>

            <div class="card">
              <h2>Upload Firmware</h2>
              <p>Upload new .bin firmware files to the server.</p>
              <a href="/upload">Upload File</a>
            </div>

            <div class="card">
              <h2>Syslog Viewer</h2>
              <p>Real-time syslog message viewer with filtering.</p>
              <a href="/syslog">View Logs</a>
            </div>

            <div class="card">
              <h2>API Documentation</h2>
              <p>Interactive API documentation powered by Swagger.</p>
              <a href="/docs">API Docs</a>
            </div>
          </div>

          <div class="api-section">
            <h2>API Endpoints</h2>
            <table class="api-table">
              <tr>
                <th>Endpoint</th>
                <th>Method</th>
                <th>Description</th>
              </tr>
              <tr>
                <td><code>/health</code></td>
                <td><span class="method method-get">GET</span></td>
                <td>Health check endpoint</td>
              </tr>
              <tr>
                <td><code>/files</code></td>
                <td><span class="method method-get">GET</span></td>
                <td>List available .bin files</td>
              </tr>
              <tr>
                <td><code>/files/{filename}</code></td>
                <td><span class="method method-get">GET</span></td>
                <td>Download a specific file</td>
              </tr>
              <tr>
                <td><code>/upload</code></td>
                <td><span class="method method-post">POST</span></td>
                <td>Upload a .bin file</td>
              </tr>
              <tr>
                <td><code>/syslog/history</code></td>
                <td><span class="method method-get">GET</span></td>
                <td>Get recent syslog entries</td>
              </tr>
              <tr>
                <td><code>/syslog/stream</code></td>
                <td><span class="method method-get">GET</span></td>
                <td>SSE stream of syslog messages</td>
              </tr>
            </table>
          </div>

          <div class="status">
            <span class="status-dot"></span>
            Server is running
          </div>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


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
    return HTMLResponse(content=_get_files_page_html())


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
    html = """
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>Syslog Viewer</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          #messages { white-space: pre-wrap; background: #f5f5f5; padding: 12px; }
          .controls { margin-bottom: 12px; }
          .controls input { margin-right: 8px; }
        </style>
      </head>
      <body>
        <h1>Syslog Viewer</h1>
        <div class="controls">
          <label>Host <input id="host" /></label>
          <label>Severity <input id="severity" /></label>
          <label>Message <input id="query" /></label>
          <button id="apply">Apply Filters</button>
        </div>
        <div id="messages"></div>
        <script>
          const messages = document.getElementById("messages");
          const hostInput = document.getElementById("host");
          const severityInput = document.getElementById("severity");
          const queryInput = document.getElementById("query");
          const applyButton = document.getElementById("apply");
          let eventSource = null;

          function entryLine(entry) {
            const sev = entry.severity_label || entry.severity || "";
            return `[${entry.timestamp}] ${entry.host} ${sev} ${entry.message}`;
          }

          async function loadHistory() {
            const params = new URLSearchParams({
              host: hostInput.value,
              severity: severityInput.value,
              q: queryInput.value
            });
            const response = await fetch(`/syslog/history?${params.toString()}`);
            const data = await response.json();
            messages.textContent = data.entries.map(entryLine).join("\\n");
          }

          function connectStream() {
            const params = new URLSearchParams({
              host: hostInput.value,
              severity: severityInput.value,
              q: queryInput.value
            });
            if (eventSource) {
              eventSource.close();
            }
            eventSource = new EventSource(`/syslog/stream?${params.toString()}`);
            eventSource.onmessage = (event) => {
              if (!event.data) {
                return;
              }
              const entry = JSON.parse(event.data);
              const line = entryLine(entry);
              messages.textContent = `${messages.textContent}\\n${line}`.trim();
            };
          }

          applyButton.addEventListener("click", async () => {
            await loadHistory();
            connectStream();
          });

          loadHistory().then(connectStream);
        </script>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


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
