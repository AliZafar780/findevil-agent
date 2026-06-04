"""Integration tests for the Find Evil MCP server."""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestMCPServer:
    """Test the MCP server tools against the forensic test image."""

    @classmethod
    def setup_class(cls):
        cls.venv_python = str(Path(__file__).parent.parent / "venv" / "bin" / "python")
        cls.test_img = "/evidence/cases/test.raw"

    async def _run_server_test(self, test_func):
        """Run a test function against the MCP server."""
        proc = await asyncio.create_subprocess_exec(
            self.venv_python, "-m", "src.server",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Initialize
        init = json.dumps({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            }
        }) + "\n"
        proc.stdin.write(init.encode())
        await proc.stdin.drain()
        await asyncio.wait_for(proc.stdout.readline(), timeout=10)

        try:
            await test_func(proc)
        finally:
            proc.kill()

    async def _call_tool(self, proc, name: str, args: dict) -> dict:
        """Call a tool and return parsed response."""
        msg = json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": args},
        }) + "\n"
        proc.stdin.write(msg.encode())
        await proc.stdin.drain()
        line = await asyncio.wait_for(proc.stdout.readline(), timeout=15)
        resp = json.loads(line)
        text = resp["result"]["content"][0]["text"]
        # Handle plain-text validation errors from MCP framework
        if resp["result"].get("isError") or text.startswith("Input validation error"):
            return {"success": False, "error": text}
        return json.loads(text)

    # ── Tests ─────────────────────────────────────────────────────

    async def test_partition_scan(self):
        """test.raw is direct ext2 (no partition table) - should fail gracefully."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_partition_scan",
                                      {"image_path": self.test_img})
            # No partition table is expected - should not crash
            assert r["success"] is False or len(r.get("partitions", [])) == 0
        await self._run_server_test(run)

    async def test_filesystem_info(self):
        """test.raw is ext2 at offset 0."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_filesystem_info",
                                      {"image_path": self.test_img, "offset": 0})
            assert r["success"] is True
            assert "ext2" in r.get("fsstat_output", "").lower() or "Ext2" in r.get("fsstat_output", "")
        await self._run_server_test(run)

    async def test_list_files(self):
        """List files without offset (direct ext2)."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_list_files",
                                      {"image_path": self.test_img, "offset": 0})
            assert r["success"] is True
            assert r["file_count"] > 0
        await self._run_server_test(run)

    async def test_file_metadata(self):
        """Get metadata for root inode (inode 2 for ext2 root)."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_file_metadata",
                                      {"image_path": self.test_img, "offset": 0, "inode": 2})
            assert r["success"] is True
        await self._run_server_test(run)

    async def test_extract_file(self):
        """Extract hello.txt at inode 20."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_extract_file",
                                      {"image_path": self.test_img, "offset": 0, "inode": 20})
            assert r["success"] is True
            assert "Hello from Find Evil" in r.get("preview", ""), f"Expected 'Hello from Find Evil', got: {r.get('preview', '')[:100]}"
        await self._run_server_test(run)

    async def test_verify_hash(self):
        """Compute SHA256 hash."""
        async def run(proc):
            r = await self._call_tool(proc, "verify_hash",
                                      {"file_path": self.test_img, "algorithm": "sha256"})
            assert r["success"] is True
            assert len(r.get("hash", "")) == 64
        await self._run_server_test(run)

    async def test_evidence_listing(self):
        """List evidence files."""
        async def run(proc):
            r = await self._call_tool(proc, "list_evidence", {"subdir": "cases"})
            assert r["success"] is True
            assert r["file_count"] >= 2
        await self._run_server_test(run)

    async def test_security_path_validation(self):
        """Path traversal should be blocked (privacy-safe error)."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_partition_scan",
                                      {"image_path": "/etc/passwd"})
            assert r["success"] is False
            err = r.get("error", "").lower()
            assert "access denied" in err or "outside evidence" in err or "not exist" in err
        await self._run_server_test(run)

    async def test_filesystem_success_without_offset(self):
        """Offset=0 works for whole-disk ext2 image."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_filesystem_info",
                                      {"image_path": self.test_img})
            assert r["success"] is True
        await self._run_server_test(run)

    async def test_security_null_byte(self):
        """Null byte in path should be rejected."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_partition_scan",
                                      {"image_path": "/evidence/cases/test.raw\x00/etc/passwd"})
            assert r["success"] is False
        await self._run_server_test(run)

    async def test_security_missing_required(self):
        """Missing required params should be rejected."""
        async def run(proc):
            r = await self._call_tool(proc, "fs_partition_scan", {})
            assert r["success"] is False
            assert "required" in r.get("error", "").lower()
        await self._run_server_test(run)


# ── Run tests ─────────────────────────────────────────────────────
if __name__ == "__main__":
    t = TestMCPServer()
    t.setup_class()

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
