"""Integration tests for the Find Evil MCP server."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

TEST_IMG = "/evidence/cases/test.raw"
HAS_EVIDENCE = Path(TEST_IMG).exists()


class TestMCPServer:
    """Test the MCP server tools against the forensic test image."""

    TEST_IMG = TEST_IMG

    async def _run_server_test(self, test_func):
        """Run a test function against the MCP server.

        Creates a fresh server subprocess per test to avoid
        event loop cross-contamination in pytest-asyncio.
        """
        from src.agent.loop import SimpleMCPClient

        client = SimpleMCPClient()
        try:
            await client.start()
            await test_func(client)
        finally:
            try:
                await client.stop()
            except Exception:
                pass

    async def _call_tool(self, client, name: str, args: dict) -> dict:
        """Call a tool and return parsed response."""
        result = await client.call_tool(name, args)
        if isinstance(result, str):
            return json.loads(result)
        if isinstance(result, dict):
            return result
        return {"success": False, "error": str(result)}

    # ── Tests ─────────────────────────────────────────────────────

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_partition_scan(self):
        """test.raw is direct ext2 (no partition table) - should fail gracefully."""

        async def run(client):
            r = await self._call_tool(client, "fs_partition_scan", {"image_path": self.TEST_IMG})
            assert r["success"] is False or len(r.get("partitions", [])) == 0

        await self._run_server_test(run)

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_filesystem_info(self):
        """test.raw is ext2 at offset 0."""

        async def run(client):
            r = await self._call_tool(
                client, "fs_filesystem_info", {"image_path": self.TEST_IMG, "offset": 0}
            )
            assert r["success"] is True
            output = (r.get("fsstat_output") or "").lower()
            assert "ext2" in output or "ext3" in output

        await self._run_server_test(run)

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_list_files(self):
        """List files without offset (direct ext2)."""

        async def run(client):
            r = await self._call_tool(
                client, "fs_list_files", {"image_path": self.TEST_IMG, "offset": 0}
            )
            assert r["success"] is True
            assert r["file_count"] > 0

        await self._run_server_test(run)

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_file_metadata(self):
        """Get metadata for root inode (inode 2 for ext2 root)."""

        async def run(client):
            r = await self._call_tool(
                client, "fs_file_metadata", {"image_path": self.TEST_IMG, "offset": 0, "inode": 2}
            )
            assert r["success"] is True

        await self._run_server_test(run)

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_extract_file(self):
        """Extract hello.txt at inode 20."""

        async def run(client):
            r = await self._call_tool(
                client, "fs_extract_file", {"image_path": self.TEST_IMG, "offset": 0, "inode": 20}
            )
            assert r["success"] is True
            preview = r.get("preview", "")
            assert (
                "Hello from Find Evil" in preview
            ), f"Expected 'Hello from Find Evil', got: {preview[:100]}"

        await self._run_server_test(run)

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_verify_hash(self):
        """Compute SHA256 hash."""

        async def run(client):
            r = await self._call_tool(
                client, "verify_hash", {"file_path": self.TEST_IMG, "algorithm": "sha256"}
            )
            assert r["success"] is True
            assert len(r.get("hash", "")) == 64

        await self._run_server_test(run)

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_evidence_listing(self):
        """List evidence files."""

        async def run(client):
            r = await self._call_tool(client, "list_evidence", {"subdir": "cases"})
            assert r["success"] is True

        await self._run_server_test(run)

    async def test_security_path_validation(self):
        """Path traversal should be blocked (privacy-safe error)."""

        async def run(client):
            r = await self._call_tool(client, "fs_partition_scan", {"image_path": "/etc/passwd"})
            assert r["success"] is False
            err = r.get("error", "").lower()
            assert any(
                w in err
                for w in ["access denied", "outside evidence", "not exist", "path validation"]
            ), f"Expected security error, got: {err}"

        await self._run_server_test(run)

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_filesystem_success_without_offset(self):
        """Offset=0 works for whole-disk ext2 image."""

        async def run(client):
            r = await self._call_tool(client, "fs_filesystem_info", {"image_path": self.TEST_IMG})
            assert r["success"] is True

        await self._run_server_test(run)

    async def test_security_null_byte(self):
        """Null byte in path should be rejected."""

        async def run(client):
            r = await self._call_tool(
                client,
                "fs_partition_scan",
                {"image_path": "/evidence/cases/test.raw\x00/etc/passwd"},
            )
            assert r["success"] is False

        await self._run_server_test(run)

    async def test_security_missing_required(self):
        """Missing required params should be rejected."""

        async def run(client):
            r = await self._call_tool(client, "fs_partition_scan", {})
            assert r["success"] is False

        await self._run_server_test(run)


# ── Run tests ─────────────────────────────────────────────────────
if __name__ == "__main__":
    t = TestMCPServer()

    async def run_all():
        tests = [
            ("partition_scan", t.test_partition_scan),
            ("filesystem_info", t.test_filesystem_info),
            ("list_files", t.test_list_files),
            ("file_metadata", t.test_file_metadata),
            ("extract_file", t.test_extract_file),
            ("verify_hash", t.test_verify_hash),
            ("evidence_listing", t.test_evidence_listing),
            ("security_path_validation", t.test_security_path_validation),
            ("filesystem_no_offset", t.test_filesystem_success_without_offset),
            ("security_null_byte", t.test_security_null_byte),
            ("security_missing_required", t.test_security_missing_required),
        ]
        passed = 0
        failed = 0
        for name, test_func in tests:
            try:
                await test_func()
                print(f"  ✅ {name}")
                passed += 1
            except Exception as e:
                print(f"  ❌ {name}: {e}")
                failed += 1

        print(f"\n{'='*40}")
        print(f"Results: {passed} passed, {failed} failed")
        return failed == 0

    success = asyncio.run(run_all())
    sys.exit(0 if success else 1)
