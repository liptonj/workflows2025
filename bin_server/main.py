"""FastAPI web server for serving .bin files with automatic detection."""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

import config
from file_watcher import BinFileWatcher

# Configure logging
logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger(__name__)

# Track available .bin files
available_files: dict[str, Path] = {}


def scan_existing_files() -> None:
    """Scan directory for existing .bin files on startup."""
    logger.info("Scanning for existing .bin files in: %s", config.BIN_DIRECTORY)
    
    for file_path in config.BIN_DIRECTORY.glob("*.bin"):
        if file_path.is_file():
            available_files[file_path.name] = file_path
            logger.info("Found existing file: %s", file_path.name)
    
    logger.info("Found %d existing .bin files", len(available_files))


def on_new_file_detected(file_path: Path) -> None:
    """Callback when a new .bin file is detected.
    
    Args:
        file_path: Path to the newly detected file.
    """
    available_files[file_path.name] = file_path
    logger.info("Added new file to serve: %s", file_path.name)


# File watcher instance
watcher: BinFileWatcher | None = None


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage application startup and shutdown.
    
    Args:
        app: FastAPI application instance.
        
    Yields:
        None during application runtime.
    """
    global watcher
    
    # Startup
    logger.info("Starting bin file server...")
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
    
    yield
    
    # Shutdown
    logger.info("Shutting down bin file server...")
    if watcher:
        watcher.stop()


app = FastAPI(
    title="Bin File Server",
    description="Automatically serves .bin files from the configured directory",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint.
    
    Returns:
        Health status response.
    """
    return {"status": "healthy"}


@app.get("/files")
async def list_files() -> dict[str, list[str]]:
    """List all available .bin files.
    
    Returns:
        List of available file names.
    """
    # Refresh list by checking which files still exist
    existing_files = []
    files_to_remove = []
    
    for filename, filepath in available_files.items():
        if filepath.exists():
            existing_files.append(filename)
        else:
            files_to_remove.append(filename)
            logger.warning("File no longer exists: %s", filename)
    
    for filename in files_to_remove:
        del available_files[filename]
    
    return {"files": sorted(existing_files)}


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


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=False,
        log_level=config.LOG_LEVEL.lower(),
    )
