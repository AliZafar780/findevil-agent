"""
Tests for the cross-source correlation engine.
"""

from pathlib import Path

import pytest

from src.tools.correlation import CorrelationEngine, _is_likely_executable, _normalize_path

# ── Stub tool caller for unit tests ───────────────────────────────────


class StubCorrelationCaller:
    """Returns configurable canned responses."""

    def __init__(self, proc_data=None, exec_data=None, network_data=None):
        self.proc_data = proc_data or []
        self.exec_data = exec_data or []
        self.network_data = network_data or []

    async def __call__(self, name, arguments):
        if name == "mem_list_processes":
            return {"success": True, "data": self.proc_data}
        if name == "fs_list_files":
            return {
                "success": True,
                "entries": self.exec_data,
                "raw_output": "\n".join(self.exec_data),
            }
        if name == "mem_scan_network":
            return {"success": True, "data": self.network_data}
        if name == "fs_filesystem_info":
            return {"success": True, "fsstat_output": "ext2"}
        return {"success": False, "error": f"unexpected tool: {name}"}


# ═══════════════════════════════════════════════════════════════════════
#  CORRELATION ENGINE — UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════


class TestCorrelationEngineInit:
    """The engine should store and validate constructor args."""

    def test_init_accepts_paths(self):
        eng = CorrelationEngine("/img.dd", "/mem.dmp")
        assert eng.disk_path == "/img.dd"
        assert eng.memory_path == "/mem.dmp"

    def test_init_default_timeout(self):
        eng = CorrelationEngine("/i", "/m")
        assert eng.analysis_timeout == 60.0

    def test_init_without_tool_caller(self):
        eng = CorrelationEngine("/i", "/m")
        assert eng._tool_caller is None


class TestCorrelationSkipsGracefully:
    """When data is missing, analyses should skip, not crash."""

    async def test_engine_returns_report_with_empty_data(self):
        eng = CorrelationEngine("/i.dd", "/m.dmp", tool_caller=StubCorrelationCaller())
        report = await eng.run()
        assert report.success is True
        assert report.total_discrepancies == 0
        assert len(report.analyses) == 4

    async def test_engine_handles_all_analyses(self):
        """All 4 analysis summaries should appear in the report."""
        eng = CorrelationEngine("/i.dd", "/m.dmp", tool_caller=StubCorrelationCaller())
        report = await eng.run()
        names = {a.name for a in report.analyses}
        assert names == {"process_file", "timeline", "network_disk", "hash_identity"}

    async def test_engine_with_no_tool_caller(self):
        """No tool caller should produce graceful skip, not exception."""
        eng = CorrelationEngine("/i.dd", "/m.dmp")
        report = await eng.run()
        assert report.success is True
        assert report.total_discrepancies == 0


class TestDiscrepancyDetection:
    """The engine should flag anomalies when given contradictory data."""

    async def test_detects_missing_executable(self):
        """Process running from path not on disk → discrepancy."""
        stub = StubCorrelationCaller(
            proc_data=[{"PID": 1337, "ImageFileName": "/tmp/injected.exe"}],
            exec_data=[r"r/r 20: normal.txt", r"r/r 21: legit.exe"],
        )
        eng = CorrelationEngine("/i.dd", "/m.dmp", tool_caller=stub)
        report = await eng.run()
        disc_types = {d.type for d in report.discrepancies}
        assert "missing_executable" in disc_types, "Should flag missing executable"

    async def test_missing_exec_is_ioc(self):
        """Missing executable should be an indicator of compromise."""
        stub = StubCorrelationCaller(
            proc_data=[{"PID": 999, "ImageFileName": "/tmp/hidden.exe"}],
            exec_data=[r"r/r 20: normal.txt", r"r/r 21: legit.exe"],
        )
        eng = CorrelationEngine("/i.dd", "/m.dmp", tool_caller=stub)
        report = await eng.run()
        ioc_discs = [d for d in report.discrepancies if d.ioc]
        assert any("missing_executable" in d.type for d in ioc_discs)

    async def test_normalizes_paths_correctly(self):
        """Paths with different formats should normalize to same."""
        assert _normalize_path("/usr/bin/bash") == "/usr/bin/bash"
        assert _normalize_path('"/usr/bin/bash"') == "/usr/bin/bash"
        assert _normalize_path("/usr/bin/Bash") == "/usr/bin/bash"
        assert _normalize_path("") == ""


class TestHelperFunctions:
    """Unit tests for pure helper functions."""

    def test_is_likely_executable(self):
        assert _is_likely_executable("malware.exe") is True
        assert _is_likely_executable("script.sh") is True
        assert _is_likely_executable("normal.txt") is False
        assert _is_likely_executable("") is False
        assert _is_likely_executable("image.png") is False
        assert _is_likely_executable("binary.elf") is True
        assert _is_likely_executable("payload.dll") is True


# ═══════════════════════════════════════════════════════════════════════
#  INTEGRATION TESTS (require MCP server + evidence files)
# ═══════════════════════════════════════════════════════════════════════

HAS_EVIDENCE = Path("/evidence/cases/test.raw").exists()
HAS_MEMORY = Path("/evidence/memory.dmp").exists()


@pytest.mark.skipif(not HAS_EVIDENCE or not HAS_MEMORY, reason="Need disk + memory evidence")
@pytest.mark.asyncio(loop_scope="module")
class TestCorrelationIntegration:
    """End-to-end correlation with real MCP client."""

    async def test_correlation_succeeds_with_real_client(self, mcp_client):
        """Integration test — will skip in CI if both sources absent."""
        report = await mcp_client.call_tool(
            "correlate_evidence",
            {
                "disk_path": "/evidence/cases/test.raw",
                "memory_path": "/evidence/memory.dmp",
            },
        )
        assert isinstance(report, dict)
        # Should either succeed or gracefully explain why it can't
        if report.get("success") is False:
            assert "error" in report
