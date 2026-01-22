"""CLI for fwserve installation and management."""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import click
import uvicorn

from fwserve import __version__

DEFAULT_INSTALL_DIR = Path("/opt/fwserve")
DEFAULT_SERVICE_USER = "fwserve"
DEFAULT_SERVICE_GROUP = "fwserve"
SERVICE_NAME = "fwserve"


@dataclass
class ExistingInstallation:
    """Information about an existing installation."""

    exists: bool
    is_legacy: bool  # True if installed via install.sh (has venv/ and main.py)
    install_dir: Path | None
    service_active: bool
    has_files: bool
    has_logs: bool


def _is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def _find_fwserve_python() -> str:
    """Find the Python interpreter that has fwserve installed.

    When running via sudo, sys.executable points to system Python,
    but fwserve might be installed in a pipx venv. This function
    finds the correct Python path.

    Returns:
        Path to the Python interpreter with fwserve installed.
    """
    # First, check if fwserve module's location gives us a hint
    import fwserve

    fwserve_path = Path(fwserve.__file__).resolve()

    # Check if it's in a pipx venv (e.g., ~/.local/share/pipx/venvs/fwserve/)
    # or similar virtual environment structure
    for parent in fwserve_path.parents:
        # Look for bin/python in a venv structure
        possible_python = parent / "bin" / "python"
        if possible_python.exists():
            return str(possible_python)

        # Also check for bin/python3
        possible_python3 = parent / "bin" / "python3"
        if possible_python3.exists():
            return str(possible_python3)

    # Fallback to sys.executable
    return sys.executable


def _user_exists(username: str) -> bool:
    """Check if a system user exists."""
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def _group_exists(groupname: str) -> bool:
    """Check if a system group exists."""
    try:
        grp.getgrnam(groupname)
        return True
    except KeyError:
        return False


def _create_group(groupname: str) -> None:
    """Create a system group."""
    subprocess.run(["groupadd", "--system", groupname], check=True)


def _create_user(username: str, groupname: str, home_dir: Path) -> None:
    """Create a system user."""
    subprocess.run(
        [
            "useradd",
            "--system",
            "--gid",
            groupname,
            "--home-dir",
            str(home_dir),
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            "--comment",
            "FWServe File Server",
            username,
        ],
        check=True,
    )


def _service_exists() -> bool:
    """Check if the systemd service file exists."""
    return Path("/etc/systemd/system/fwserve.service").exists()


def _service_is_active() -> bool:
    """Check if the systemd service is currently running."""
    result = subprocess.run(
        ["systemctl", "is-active", SERVICE_NAME],  # noqa: S603, S607
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() == "active"


def _detect_existing_installation(install_dir: Path) -> ExistingInstallation:
    """Detect if there's an existing installation and its type.

    Args:
        install_dir: The installation directory to check.

    Returns:
        ExistingInstallation with details about what was found.
    """
    if not install_dir.exists():
        return ExistingInstallation(
            exists=False,
            is_legacy=False,
            install_dir=None,
            service_active=False,
            has_files=False,
            has_logs=False,
        )

    # Check for legacy install.sh markers
    # Legacy installs have Python files at the root level (main.py, config.py)
    # New installs only have venv/, files/, logs/ directories
    legacy_markers = [
        install_dir / "main.py",  # Old main module at root
        install_dir / "config.py",  # Old config at root
        install_dir / "file_watcher.py",  # Old module at root
    ]
    is_legacy = any(marker.exists() for marker in legacy_markers)

    files_dir = install_dir / "files"
    logs_dir = install_dir / "logs"

    return ExistingInstallation(
        exists=True,
        is_legacy=is_legacy,
        install_dir=install_dir,
        service_active=_service_is_active() if _service_exists() else False,
        has_files=files_dir.exists() and any(files_dir.iterdir()),
        has_logs=logs_dir.exists() and any(logs_dir.iterdir()),
    )


def _stop_service() -> None:
    """Stop the systemd service if running."""
    subprocess.run(["systemctl", "stop", SERVICE_NAME], check=False)


def _migrate_legacy_installation(install_dir: Path) -> None:
    """Remove legacy install.sh artifacts while preserving data.

    Args:
        install_dir: The installation directory.
    """
    legacy_files = [
        "main.py",
        "config.py",
        "file_watcher.py",
        "syslog_parser.py",
        "syslog_store.py",
        "syslog_server.py",
        "pyproject.toml",
        "README.md",
        "add_file.sh",
        "install.sh",
        "bin_server.service",
    ]

    for filename in legacy_files:
        filepath = install_dir / filename
        if filepath.exists():
            filepath.unlink()

    # Remove old venv
    venv_dir = install_dir / "venv"
    if venv_dir.exists():
        shutil.rmtree(venv_dir)


def _get_service_template() -> str:
    """Get the systemd service template."""
    return """[Unit]
Description=FWServe - Firmware file server with upload UI and syslog receiver
After=network.target
Wants=network-online.target

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={install_dir}
ExecStart={python_path} -m uvicorn fwserve.app:app --host 0.0.0.0 --port {port}
Restart=always
RestartSec=5

# Environment variables - Server
Environment="FWSERVE_HOST=0.0.0.0"
Environment="FWSERVE_PORT={port}"
Environment="FWSERVE_DIRECTORY={files_dir}"
Environment="FWSERVE_LOG_LEVEL=INFO"
Environment="FWSERVE_TIMEZONE=America/New_York"

# Environment variables - Upload
Environment="FWSERVE_UPLOAD_MAX_BYTES=10737418240"

# Environment variables - Syslog
Environment="SYSLOG_ENABLE_UDP=true"
Environment="SYSLOG_ENABLE_TCP=true"
Environment="SYSLOG_UDP_PORT={syslog_port}"
Environment="SYSLOG_TCP_PORT={syslog_port}"
Environment="SYSLOG_LOG_FILE={logs_dir}/syslog.log"
Environment="SYSLOG_TAIL_SIZE=5000"

# Security hardening - allow binding to privileged ports as non-root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=false
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={files_dir} {logs_dir}
ReadOnlyPaths={install_dir}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fwserve

[Install]
WantedBy=multi-user.target
"""


@click.group()
@click.version_option(version=__version__)
def cli() -> None:
    """FWServe - Firmware file server with syslog receiver."""
    pass  # pylint: disable=unnecessary-pass


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8080, type=int, help="Port to listen on")
@click.option("--directory", default=".", help="Directory to serve files from")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def run(host: str, port: int, directory: str, reload: bool) -> None:
    """Run the server in development mode."""
    os.environ["FWSERVE_HOST"] = host
    os.environ["FWSERVE_PORT"] = str(port)
    os.environ["FWSERVE_DIRECTORY"] = directory

    click.echo(f"Starting fwserve on {host}:{port}")
    click.echo(f"Serving files from: {directory}")
    click.echo(f"Upload UI: http://{host}:{port}/upload")
    click.echo(f"Syslog UI: http://{host}:{port}/syslog")

    uvicorn.run(
        "fwserve.app:app",
        host=host,
        port=port,
        reload=reload,
    )


@cli.command()
@click.option(
    "--install-dir",
    type=click.Path(),
    default=str(DEFAULT_INSTALL_DIR),
    help="Installation directory",
)
@click.option("--user", default=DEFAULT_SERVICE_USER, help="Service user")
@click.option("--group", default=DEFAULT_SERVICE_GROUP, help="Service group")
@click.option("--port", default=80, type=int, help="HTTP port")
@click.option("--syslog-port", default=514, type=int, help="Syslog UDP/TCP port")
@click.option("--no-service", is_flag=True, help="Skip systemd service installation")
@click.option("--force", is_flag=True, help="Force installation even if existing found")
def install(
    install_dir: str,
    user: str,
    group: str,
    port: int,
    syslog_port: int,
    no_service: bool,
    force: bool,
) -> None:
    """Install fwserve as a systemd service (requires root)."""
    if not _is_root():
        click.echo("Error: This command must be run as root (use sudo)", err=True)
        sys.exit(1)

    install_path = Path(install_dir)
    files_dir = install_path / "files"
    logs_dir = install_path / "logs"

    # Detect existing installation
    existing = _detect_existing_installation(install_path)

    if existing.exists:
        if existing.is_legacy:
            click.echo("Detected existing install.sh-based installation")
            if existing.has_files:
                click.echo(f"  - Found existing files in {files_dir}")
            if existing.has_logs:
                click.echo(f"  - Found existing logs in {logs_dir}")

            if not force:
                if not click.confirm("Migrate to pip-based installation? (data will be preserved)"):
                    click.echo("Aborted")
                    sys.exit(0)

            if existing.service_active:
                click.echo("Stopping existing service...")
                _stop_service()

            click.echo("Migrating from legacy installation...")
            _migrate_legacy_installation(install_path)
            click.echo("Legacy files removed, data preserved")
        else:
            click.echo("Detected existing pip-based installation")
            if not force:
                if not click.confirm("Update existing installation?"):
                    click.echo("Aborted")
                    sys.exit(0)

            if existing.service_active:
                click.echo("Stopping existing service...")
                _stop_service()

    click.echo(f"Installing fwserve to {install_path}")

    # Create group
    if not _group_exists(group):
        click.echo(f"Creating group: {group}")
        _create_group(group)
    else:
        click.echo(f"Group {group} already exists")

    # Create user
    if not _user_exists(user):
        click.echo(f"Creating user: {user}")
        _create_user(user, group, install_path)
    else:
        click.echo(f"User {user} already exists")

    # Create directories
    click.echo("Creating directories...")
    install_path.mkdir(parents=True, exist_ok=True)
    files_dir.mkdir(exist_ok=True)
    logs_dir.mkdir(exist_ok=True)

    # Set ownership for install directory
    click.echo("Setting permissions...")
    shutil.chown(install_path, user=user, group=group)
    shutil.chown(files_dir, user=user, group=group)
    shutil.chown(logs_dir, user=user, group=group)
    os.chmod(install_path, 0o755)
    os.chmod(files_dir, 0o755)
    os.chmod(logs_dir, 0o755)

    # Create virtual environment in install directory
    venv_dir = install_path / "venv"
    if venv_dir.exists():
        click.echo("Removing existing virtual environment...")
        shutil.rmtree(venv_dir)
    click.echo(f"Creating virtual environment in {venv_dir}...")
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)

    # Install fwserve into the venv
    venv_pip = venv_dir / "bin" / "pip"
    click.echo("Installing fwserve into virtual environment...")
    subprocess.run(
        [str(venv_pip), "install", "--upgrade", "fwserve"],
        check=True,
    )

    # Set ownership for venv
    shutil.chown(venv_dir, user=user, group=group)
    for root, dirs, files in os.walk(venv_dir):
        for d in dirs:
            shutil.chown(os.path.join(root, d), user=user, group=group)
        for f in files:
            shutil.chown(os.path.join(root, f), user=user, group=group)

    # Use the venv Python
    python_path = str(venv_dir / "bin" / "python")
    click.echo(f"Using Python: {python_path}")

    # Install systemd service
    if not no_service:
        click.echo("Installing systemd service...")
        service_content = _get_service_template().format(
            user=user,
            group=group,
            install_dir=install_path,
            python_path=python_path,
            port=port,
            files_dir=files_dir,
            logs_dir=logs_dir,
            syslog_port=syslog_port,
        )

        service_path = Path("/etc/systemd/system/fwserve.service")
        service_path.write_text(service_content, encoding="utf-8")

        subprocess.run(["systemctl", "daemon-reload"], check=True)
        click.echo("Systemd service installed")

    click.echo("")
    click.echo("Installation complete!")
    click.echo("")
    click.echo("To start the service:")
    click.echo("  sudo systemctl start fwserve")
    click.echo("")
    click.echo("To enable on boot:")
    click.echo("  sudo systemctl enable fwserve")
    click.echo("")
    click.echo("Server endpoints:")
    click.echo(f"  Files API:  http://localhost:{port}/files")
    click.echo(f"  Upload UI:  http://localhost:{port}/upload")
    click.echo(f"  Syslog UI:  http://localhost:{port}/syslog")
    click.echo("")
    click.echo(f"Syslog listening on UDP/TCP port {syslog_port}")


@cli.command()
def uninstall() -> None:
    """Uninstall the systemd service (requires root)."""
    if not _is_root():
        click.echo("Error: This command must be run as root (use sudo)", err=True)
        sys.exit(1)

    service_path = Path("/etc/systemd/system/fwserve.service")

    if not service_path.exists():
        click.echo("Service is not installed")
        return

    click.echo("Stopping service...")
    subprocess.run(["systemctl", "stop", "fwserve"], check=False)
    subprocess.run(["systemctl", "disable", "fwserve"], check=False)

    click.echo("Removing service file...")
    service_path.unlink()

    subprocess.run(["systemctl", "daemon-reload"], check=True)

    click.echo("Service uninstalled")
    click.echo("")
    click.echo("Note: Data directories were NOT removed.")
    click.echo("To remove manually: sudo rm -rf /opt/fwserve")


@cli.command()
def status() -> None:
    """Show service status."""
    result = subprocess.run(
        ["systemctl", "is-active", "fwserve"],
        capture_output=True,
        text=True,
        check=False,
    )
    is_active = result.stdout.strip() == "active"

    if is_active:
        click.echo("fwserve: running")
    else:
        click.echo(f"fwserve: {result.stdout.strip()}")

    # Show more details
    subprocess.run(["systemctl", "status", "fwserve", "--no-pager", "-l"], check=False)


def main() -> None:
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
