"""Shared test fixtures and configuration for edge case test suite.

Uses a singleton MCP client to avoid restarting the server per test.
"""

import sys as _sys
from pathlib import Path as _Path

import pytest

_sys.path.insert(0, str(_Path(__file__).parent.parent))

# Shared helpers and constants from helpers.py
from helpers import EVIDENCE_ROOT, HAS_EVIDENCE, _call  # noqa: E402, F401

# ── Singleton MCP client ──────────────────────────────────────────

_CLIENT_INSTANCE = None


@pytest.fixture(scope="module")
async def mcp_client():
    """Singleton MCP server client — shared across all tests in this module.

    Starts the server once on first use, shuts it down during teardown.
    Avoids restarting the subprocess for every test (saves ~30s+).
    """
    global _CLIENT_INSTANCE
    from src.agent.loop import SimpleMCPClient

    if _CLIENT_INSTANCE is None:
        _CLIENT_INSTANCE = SimpleMCPClient()
        await _CLIENT_INSTANCE.start()
        # Give the server a moment to settle after init handshake
        import asyncio

        await asyncio.sleep(0.1)

    yield _CLIENT_INSTANCE

    # Module teardown — only stop once when pytest collects the last
    # module-scoped fixture teardown across all test files.
    if _CLIENT_INSTANCE is not None:
        try:
            await _CLIENT_INSTANCE.stop()
        except Exception:
            pass
        _CLIENT_INSTANCE = None


@pytest.fixture(scope="module")
def test_img():
    """Path to test evidence file, or a sentinel for skipif checks."""
    return str(EVIDENCE_ROOT) if EVIDENCE_ROOT.exists() else "/nonexistent"
