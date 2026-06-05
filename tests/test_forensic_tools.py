"""Unit tests for individual forensic tool modules (no MCP server needed)."""
import sys
import json
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestHashingTools:
    """Test hashing module directly."""

    def test_hash_result_model(self):
        """HashResult Pydantic model works."""
        from src.tools.hashing import HashResult
        r = HashResult(success=True, algorithm="sha256", hash_value="abc123")
        assert r.success is True
        assert r.algorithm == "sha256"
        assert r.hash_value == "abc123"

    def test_hash_result_failure(self):
        """HashResult can represent failures."""
        from src.tools.hashing import HashResult
        r = HashResult(success=False, error="File not found")
        assert r.success is False
        assert "not found" in r.error


class TestPatternTools:
    """Test pattern detection module."""

    def test_pattern_result_model(self):
        """PatternResult Pydantic model works."""
        from src.tools.patterns import PatternResult
        r = PatternResult(success=True, match_count=5)
        assert r.success is True
        assert r.match_count == 5

    def test_builtin_rules_exist(self):
        """Built-in YARA rules are non-empty."""
        from src.tools.patterns import BUILTIN_RULES
        assert len(BUILTIN_RULES) > 100
        assert "rule " in BUILTIN_RULES

    def test_search_text_patterns_empty(self):
        """search_text_patterns handles empty patterns gracefully."""
        from src.tools.patterns import search_text_patterns
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("Hello World\nTest line\n")
            tmp = f.name
        try:
            result = search_text_patterns(tmp, [])
            assert result.success is True
            assert result.match_count == 0
        finally:
            Path(tmp).unlink(missing_ok=True)


class TestFilesystemTools:
    """Test filesystem analysis module."""

    def test_filesystem_result_model(self):
        """FileSystemResult Pydantic model works."""
        from src.tools.filesystem import FileSystemResult
        r = FileSystemResult(data=[{"name": "test.txt"}])
        assert r.success is True
        assert len(r.data) == 1

    def test_partition_model(self):
        """Partition Pydantic model works."""
        from src.tools.filesystem import Partition
        p = Partition(slot=0, start=2048, end=4096, length=2048, description="Linux")
        assert p.slot == 0
        assert p.start == 2048

    def test_file_entry_model(self):
        """FileEntry Pydantic model works."""
        from src.tools.filesystem import FileEntry
        entry = FileEntry(name="test.txt", inode=123, file_type="file")
        assert entry.name == "test.txt"
        assert entry.inode == 123


class TestRegistryTools:
    """Test registry analysis module."""

    def test_registry_result_model(self):
        """RegistryResult Pydantic model works."""
        from src.tools.registry import RegistryResult
        r = RegistryResult(key_count=10, data=[{"path": "/test"}])
        assert r.key_count == 10
        assert r.success is True


class TestNetworkTools:
    """Test network analysis module."""

    def test_network_result_model(self):
        """NetworkResult Pydantic model works."""
        from src.tools.network import NetworkResult
        r = NetworkResult(packet_count=100, data=[{"frame": "1"}])
        assert r.packet_count == 100
        assert r.success is True


class TestTimelineTools:
    """Test timeline analysis module."""

    def test_timeline_result_model(self):
        """TimelineResult Pydantic model works."""
        from src.tools.timeline import TimelineResult
        r = TimelineResult(event_count=50, storage_path="/tmp/test.plaso")
        assert r.event_count == 50
        assert r.storage_path == "/tmp/test.plaso"


class TestMemoryTools:
    """Test memory analysis module."""

    def test_memory_result_model(self):
        """MemoryResult Pydantic model works."""
        from src.tools.memory import MemoryResult
        r = MemoryResult(plugin="linux.pslist", data=[{"PID": 1}])
        assert r.plugin == "linux.pslist"
        assert r.success is True

    def test_vol_candidates_exists(self):
        """Volatility candidate paths are defined."""
        from src.tools.memory import VOL_CANDIDATES
        assert len(VOL_CANDIDATES) >= 4
        assert all(isinstance(p, str) for p in VOL_CANDIDATES)


class TestToolResolver:
    """Test cross-platform tool resolution."""

    def test_find_tool_returns_none_for_bogus(self):
        """find_tool returns None for non-existent tools."""
        from src.tools.tool_resolver import find_tool
        result = find_tool("this_tool_does_not_exist_xyz")
        assert result is None

    def test_find_tools_batch(self):
        """find_tools returns dict of results."""
        from src.tools.tool_resolver import find_tools
        results = find_tools("python3", "this_tool_does_not_exist_xyz")
        assert "python3" in results
        assert "this_tool_does_not_exist_xyz" in results
        # python3 should be found
        assert results["python3"] is not None
