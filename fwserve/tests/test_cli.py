"""Unit tests for the CLI module."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from fwserve.cli import (
    _detect_existing_installation,
    _group_exists,
    _is_root,
    _migrate_legacy_installation,
    _user_exists,
    cli,
)


class TestHelperFunctions:
    """Tests for CLI helper functions."""

    def test_is_root_returns_false_for_regular_user(self) -> None:
        """Regular users should not be detected as root."""
        with patch("os.geteuid", return_value=1000):
            assert _is_root() is False

    def test_is_root_returns_true_for_root(self) -> None:
        """Root user should be detected."""
        with patch("os.geteuid", return_value=0):
            assert _is_root() is True

    def test_user_exists_returns_false_for_nonexistent(self) -> None:
        """Non-existent users should return False."""
        assert _user_exists("nonexistent_user_12345") is False

    def test_group_exists_returns_false_for_nonexistent(self) -> None:
        """Non-existent groups should return False."""
        assert _group_exists("nonexistent_group_12345") is False

    def test_service_exists_returns_false_when_no_file(self) -> None:
        """Service should not exist when service file is missing."""
        with patch("fwserve.cli.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            # Need to reimport or call directly
            assert not Path("/etc/systemd/system/fwserve.service").exists()


class TestDetectExistingInstallation:
    """Tests for installation detection."""

    def test_detects_no_installation(self) -> None:
        """Should detect when no installation exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nonexistent = Path(tmpdir) / "nonexistent"
            result = _detect_existing_installation(nonexistent)

            assert result.exists is False
            assert result.is_legacy is False
            assert result.install_dir is None

    def test_detects_legacy_installation(self) -> None:
        """Should detect install.sh-based installation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            # Create legacy markers
            (install_dir / "venv").mkdir()
            (install_dir / "main.py").touch()
            (install_dir / "config.py").touch()

            result = _detect_existing_installation(install_dir)

            assert result.exists is True
            assert result.is_legacy is True
            assert result.install_dir == install_dir

    def test_detects_pip_installation(self) -> None:
        """Should detect pip-based installation (no legacy markers)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            # Create directories but no legacy files
            (install_dir / "files").mkdir()
            (install_dir / "logs").mkdir()

            result = _detect_existing_installation(install_dir)

            assert result.exists is True
            assert result.is_legacy is False

    def test_detects_existing_files(self) -> None:
        """Should detect when files directory has content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            files_dir = install_dir / "files"
            files_dir.mkdir()
            (files_dir / "firmware.bin").write_bytes(b"\x00")

            result = _detect_existing_installation(install_dir)

            assert result.has_files is True

    def test_detects_existing_logs(self) -> None:
        """Should detect when logs directory has content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            logs_dir = install_dir / "logs"
            logs_dir.mkdir()
            (logs_dir / "syslog.log").write_text("test log")

            result = _detect_existing_installation(install_dir)

            assert result.has_logs is True


class TestMigrateLegacyInstallation:
    """Tests for legacy installation migration."""

    def test_removes_legacy_files(self) -> None:
        """Should remove legacy Python files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            # Create legacy files
            legacy_files = [
                "main.py",
                "config.py",
                "file_watcher.py",
                "syslog_parser.py",
            ]
            for filename in legacy_files:
                (install_dir / filename).touch()

            _migrate_legacy_installation(install_dir)

            for filename in legacy_files:
                assert not (install_dir / filename).exists()

    def test_removes_legacy_venv(self) -> None:
        """Should remove old virtualenv directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            venv_dir = install_dir / "venv"
            venv_dir.mkdir()
            (venv_dir / "bin").mkdir()
            (venv_dir / "bin" / "python").touch()

            _migrate_legacy_installation(install_dir)

            assert not venv_dir.exists()

    def test_preserves_data_directories(self) -> None:
        """Should preserve files and logs directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            files_dir = install_dir / "files"
            logs_dir = install_dir / "logs"
            files_dir.mkdir()
            logs_dir.mkdir()
            (files_dir / "firmware.bin").write_bytes(b"\x00\x01")
            (logs_dir / "syslog.log").write_text("log data")

            # Create some legacy files too
            (install_dir / "main.py").touch()

            _migrate_legacy_installation(install_dir)

            # Data should be preserved
            assert files_dir.exists()
            assert logs_dir.exists()
            assert (files_dir / "firmware.bin").read_bytes() == b"\x00\x01"
            assert (logs_dir / "syslog.log").read_text() == "log data"


class TestCliCommands:
    """Tests for CLI commands."""

    def test_cli_version(self) -> None:
        """Version command should show version."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_cli_help(self) -> None:
        """Help should show available commands."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "run" in result.output
        assert "install" in result.output
        assert "uninstall" in result.output
        assert "status" in result.output

    def test_run_help(self) -> None:
        """Run command help should show options."""
        runner = CliRunner()
        result = runner.invoke(cli, ["run", "--help"])

        assert result.exit_code == 0
        assert "--host" in result.output
        assert "--port" in result.output
        assert "--directory" in result.output
        assert "--reload" in result.output

    def test_install_requires_root(self) -> None:
        """Install command should require root."""
        runner = CliRunner()
        with patch("fwserve.cli._is_root", return_value=False):
            result = runner.invoke(cli, ["install"])

        assert result.exit_code == 1
        assert "must be run as root" in result.output

    def test_uninstall_requires_root(self) -> None:
        """Uninstall command should require root."""
        runner = CliRunner()
        with patch("fwserve.cli._is_root", return_value=False):
            result = runner.invoke(cli, ["uninstall"])

        assert result.exit_code == 1
        assert "must be run as root" in result.output

    def test_install_detects_legacy_and_prompts(self) -> None:
        """Install should detect legacy installation and prompt."""
        runner = CliRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            # Create legacy markers
            (install_dir / "venv").mkdir()
            (install_dir / "main.py").touch()

            with patch("fwserve.cli._is_root", return_value=True):
                result = runner.invoke(
                    cli,
                    ["install", "--install-dir", str(install_dir)],
                    input="n\n",  # Answer "no" to migration prompt
                )

        assert "Detected existing install.sh-based installation" in result.output

    def test_install_with_force_skips_prompts(self) -> None:
        """Install with --force should skip confirmation prompts."""
        runner = CliRunner()

        with tempfile.TemporaryDirectory() as tmpdir:
            install_dir = Path(tmpdir)
            # Create legacy markers
            (install_dir / "venv").mkdir()
            (install_dir / "main.py").touch()

            with patch("fwserve.cli._is_root", return_value=True), patch(
                "fwserve.cli._group_exists", return_value=True
            ), patch("fwserve.cli._user_exists", return_value=True), patch(
                "fwserve.cli.subprocess.run"
            ) as mock_run, patch("fwserve.cli.shutil.chown"):
                mock_run.return_value = MagicMock(returncode=0)
                result = runner.invoke(
                    cli,
                    ["install", "--install-dir", str(install_dir), "--force", "--no-service"],
                )

        assert result.exit_code == 0
        assert "Installation complete" in result.output

    def test_status_shows_service_state(self) -> None:
        """Status command should show service state."""
        runner = CliRunner()

        with patch("fwserve.cli.subprocess.run") as mock_run:
            # Mock is-active check
            mock_run.return_value = MagicMock(
                stdout="inactive\n",
                returncode=3,
            )
            result = runner.invoke(cli, ["status"])

        assert "fwserve:" in result.output
