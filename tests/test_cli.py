"""Tests for the CLI entry point."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCLI:
    """Test CLI entry point."""

    def test_cli_import(self):
        """CLI module imports without error."""
        from src.cli import main
        assert callable(main)

    def test_cli_get_version(self):
        """CLI reports version."""
        from src.cli import _get_version
        version = _get_version()
        assert version is not None
        assert isinstance(version, str)
        assert len(version) > 0

    def test_cli_print_logo(self):
        """Logo generation works."""
        from src.cli import _print_logo
        # Function should exist and be callable
        assert callable(_print_logo)

    def test_cli_help_runs(self):
        """CLI --help exits successfully."""
        import subprocess
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "usage" in result.stderr.lower()
