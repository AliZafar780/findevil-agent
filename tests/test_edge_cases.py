"""
Comprehensive Edge Case & Failure Mode Test Suite — pytest edition.

Tests every tool against:
  - Missing/nonexistent evidence
  - Empty/invalid arguments
  - Path traversal attacks (security)
  - Wrong tool for evidence type
  - Malformed input
  - Large files
  - Permission errors
  - Output directory validation
  - Audit trail integrity
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── Helpers ────────────────────────────────────────────────────────

EVIDENCE_ROOT = Path("/evidence/cases/test.raw")
HAS_EVIDENCE = EVIDENCE_ROOT.exists()


async def _call(client, name: str, args: dict) -> dict:
    """Call a tool and return parsed result."""
    result = await client.call_tool(name, args)
    if isinstance(result, str):
        return json.loads(result)
    return result if isinstance(result, dict) else {"success": False, "error": str(result)}


def _get_client():
    """Create a fresh SimpleMCPClient for each test.
    
    Each test gets its own MCP server subprocess to avoid
    event loop attachment issues across async tests.
    """
    from src.agent.loop import SimpleMCPClient
    return SimpleMCPClient()


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture(scope="function")
async def mcp_client():
    """Start a fresh MCP server per test.
    
    Function-scoped to avoid asyncio event loop cross-contamination
    (each async test in pytest-asyncio gets its own event loop).
    Integration tests require system forensic tools installed.
    """
    client = _get_client()
    await client.start()
    yield client
    try:
        await client.stop()
    except Exception:
        pass


@pytest.fixture
def test_img():
    return "/evidence/cases/test.raw"


# ═════════════════════════════════════════════════════════════════
# 1. SECURITY: PATH TRAVERSAL ATTACKS
# ═════════════════════════════════════════════════════════════════


class TestPathTraversal:
    """Tools must reject paths outside the evidence root."""

    TRAVERSAL_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/evidence/../../etc/hosts",
        "/evidence/../../../root/.ssh/id_rsa",
        "/evidence/cases/../../../../../etc/ssl/private/key.pem",
        "~/.bash_history",
        "/proc/1/environ",
        "/sys/kernel/security/current_policy",
    ]

    @pytest.mark.parametrize("path", TRAVERSAL_PATHS)
    async def test_path_traversal_blocked(self, mcp_client, path):
        r = await _call(mcp_client, "fs_partition_scan", {"image_path": path})
        assert not r.get("success"), f"Path should be blocked: {path}"
        err = (r.get("error") or "").lower()
        assert any(w in err for w in ["access denied", "not exist", "outside evidence"]), (
            f"Expected security error, got: {err}"
        )

    @pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
    async def test_subdir_traversal_blocked(self, mcp_client):
        r = await _call(mcp_client, "list_evidence", {"subdir": "../"})
        assert not r.get("success"), "Subdir traversal should be blocked"

    async def test_subdir_deep_traversal_blocked(self, mcp_client):
        r = await _call(mcp_client, "list_evidence", {"subdir": "../../etc/"})
        assert not r.get("success"), "Deep subdir traversal should be blocked"

    async def test_null_byte_blocked(self, mcp_client):
        # Null byte test doesn't need a real file - just a path with embedded null
        r = await _call(mcp_client, "fs_partition_scan", {"image_path": "/evidence/cases/test.raw\x00/etc/passwd"})
        assert not r.get("success"), "Null byte injection should be blocked"

    async def test_missing_required_params(self, mcp_client):
        r = await _call(mcp_client, "fs_partition_scan", {})
        assert not r.get("success"), "Missing required params should fail"


class TestMissingEvidence:
    """Tools must handle missing files gracefully."""

    MISSING_PATH = "/nonexistent/path.raw"

    @pytest.mark.parametrize("tool,args", [
        ("fs_partition_scan", {"image_path": "/nonexistent/path.raw"}),
        ("fs_list_files", {"image_path": "/nonexistent/path.raw"}),
        ("fs_filesystem_info", {"image_path": "/nonexistent/path.raw"}),
        ("verify_hash", {"file_path": "/nonexistent/path.raw", "algorithm": "sha256"}),
    ])
    async def test_tool_with_missing_path(self, mcp_client, tool, args):
        r = await _call(mcp_client, tool, args)
        assert not r.get("success"), f"{tool} should fail with missing path"
        assert r.get("error"), f"{tool} should provide error message"

    async def test_carve_missing_image(self, mcp_client):
        r = await _call(mcp_client, "carve_files", {
            "image_path": "/nonexistent/img.raw",
            "output_dir": "/results/carved/test",
        })
        assert not r.get("success"), "Carve with missing image should fail"

    async def test_yara_missing_target(self, mcp_client):
        r = await _call(mcp_client, "scan_yara", {
            "target": "/nonexistent/file.bin",
            "rules": "rule t { condition: true }",
        })
        assert not r.get("success"), "YARA with missing target should fail"

    async def test_extract_missing_image(self, mcp_client):
        r = await _call(mcp_client, "fs_extract_file", {
            "image_path": "/nonexistent/img.raw",
            "inode": 1,
        })
        assert not r.get("success"), "Extract with missing image should fail"


class TestInvalidArguments:
    """Tools must reject invalid/empty arguments."""

    async def test_empty_path_partition(self, mcp_client):
        r = await _call(mcp_client, "fs_partition_scan", {"image_path": ""})
        assert not r.get("success"), "Empty path should fail"

    async def test_empty_path_hash(self, mcp_client):
        r = await _call(mcp_client, "verify_hash", {"file_path": "", "algorithm": "sha256"})
        assert not r.get("success"), "Empty path hash should fail"

    async def test_negative_inode(self, mcp_client, test_img):
        r = await _call(mcp_client, "fs_extract_file", {"image_path": test_img, "inode": -1})
        assert not r.get("success"), "Negative inode should fail"

    async def test_zero_inode(self, mcp_client, test_img):
        r = await _call(mcp_client, "fs_extract_file", {"image_path": test_img, "inode": 0})
        assert not r.get("success"), "Zero inode should fail"

    async def test_nonexistent_inode(self, mcp_client, test_img):
        r = await _call(mcp_client, "fs_extract_file", {"image_path": test_img, "inode": 9999999})
        assert not r.get("success"), "Nonexistent inode should fail"

    async def test_invalid_hash_algorithm(self, mcp_client, test_img):
        r = await _call(mcp_client, "verify_hash", {
            "file_path": test_img,
            "algorithm": "invalid_algorithm",
        })
        assert not r.get("success"), "Invalid hash algorithm should fail"

    async def test_empty_yara_rules(self, mcp_client, test_img):
        r = await _call(mcp_client, "scan_yara", {"target": test_img, "rules": ""})
        assert not r.get("success"), "Empty YARA rules should fail"

    async def test_malformed_yara_rules(self, mcp_client, test_img):
        r = await _call(mcp_client, "scan_yara", {
            "target": test_img,
            "rules": "not valid yara @@@ ###",
        })
        assert not r.get("success"), "Malformed YARA rules should fail"


@pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
class TestWrongToolForEvidence:
    """Tools must reject evidence of the wrong type."""

    async def test_memory_tool_on_disk(self, mcp_client, test_img):
        r = await _call(mcp_client, "mem_list_processes", {"memory_path": test_img})
        # Server gracefully falls back to string-based IOC scanning if Volatility can't parse
        if r.get("success"):
            data = r.get("data", [])
            if data:
                assert any("fallback" in (d.get("plugin") or "") or "string-based" in (d.get("note") or "") for d in data), \
                    "Expected fallback IOC scan, not full memory analysis"

    async def test_memory_analyze_on_disk(self, mcp_client, test_img):
        r = await _call(mcp_client, "mem_analyze", {"memory_path": test_img})
        # Server gracefully falls back to string-based IOC scanning if Volatility can't parse
        if r.get("success"):
            data = r.get("data", [])
            if data:
                assert any("fallback" in (d.get("plugin") or "") or "string-based" in (d.get("note") or "") for d in data), \
                    "Expected fallback IOC scan, not full memory analysis"

    async def test_registry_tool_on_disk(self, mcp_client, test_img):
        r = await _call(mcp_client, "reg_analyze_hive", {"hive_path": test_img})
        assert not r.get("success"), "Registry tool on disk image should fail"

    async def test_pcap_tool_on_disk(self, mcp_client, test_img):
        r = await _call(mcp_client, "pcap_analyze", {"pcap_path": test_img})
        assert not r.get("success"), "PCAP tool on disk image should fail"

    async def test_pcap_protocols_on_disk(self, mcp_client, test_img):
        r = await _call(mcp_client, "pcap_list_protocols", {"pcap_path": test_img})
        assert not r.get("success"), "PCAP protocols on disk image should fail"


@pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
class TestCarvingEdgeCases:
    """Carve tool must handle output dir security and empty results."""

    FORBIDDEN_DIRS = ["/etc", "/var", "/tmp", "/home", "/root",
                      "/bin", "/usr", "/boot", "/dev"]

    @pytest.mark.parametrize("dir_path", FORBIDDEN_DIRS)
    async def test_carve_to_forbidden_dir(self, mcp_client, test_img, dir_path):
        r = await _call(mcp_client, "carve_files", {
            "image_path": test_img,
            "output_dir": f"{dir_path}/carved",
        })
        assert not r.get("success"), f"Carve to {dir_path} should be blocked"

    async def test_carve_with_empty_output_dir(self, mcp_client, test_img):
        r = await _call(mcp_client, "carve_files", {
            "image_path": test_img,
            "output_dir": "",
        })
        assert not r.get("success"), "Carve with empty output dir should fail"


@pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
class TestYaraEdgeCases:
    """YARA tool must handle no-match, match, and bad rules."""

    async def test_yara_no_match(self, mcp_client, test_img):
        r = await _call(mcp_client, "scan_yara", {
            "target": test_img,
            "rules": "rule nevermatch { condition: false }",
        })
        assert r.get("success"), "YARA with no match should succeed (clean)"
        assert r.get("match_count", -1) == 0, "Should have zero matches"

    async def test_yara_with_match(self, mcp_client, test_img):
        r = await _call(mcp_client, "scan_yara", {
            "target": test_img,
            "rules": "rule FindEvil { strings: $m = \"malware\" $h = \"Find Evil\" condition: any of them }",
        })
        assert r.get("success"), "YARA with matching rule should succeed"
        assert r.get("match_count", 0) > 0, "Should have at least one match"

    async def test_yara_empty_target(self, mcp_client):
        r = await _call(mcp_client, "scan_yara", {
            "target": "",
            "rules": "rule t { condition: true }",
        })
        assert not r.get("success"), "YARA with empty target should fail"


@pytest.mark.skipif(not HAS_EVIDENCE, reason="Test evidence file required")
class TestLargeFileHandling:
    """Tools must handle large files without crashing."""

    async def test_large_file_hash(self, mcp_client):
        large_path = "/evidence/cases/large_test.bin"
        try:
            with open(large_path, "wb") as f:
                f.write(b"X" * 50 * 1024 * 1024)  # 50MB

            for alg in ["md5", "sha1", "sha256"]:
                r = await _call(mcp_client, "verify_hash", {
                    "file_path": large_path,
                    "algorithm": alg,
                })
                assert r.get("success"), f"Hash of 50MB file with {alg} should succeed"
                assert r.get("hash"), "Should return a hash value"
        finally:
            if os.path.exists(large_path):
                os.unlink(large_path)


class TestAuditTrail:
    """Audit logs must be retrievable and well-formed."""

    async def test_audit_logs_retrievable(self, mcp_client):
        r = await _call(mcp_client, "get_audit_logs", {"limit": 1000})
        assert r.get("success"), "Audit logs should be retrievable"

    async def test_audit_entries_have_required_fields(self, mcp_client):
        r = await _call(mcp_client, "get_audit_logs", {"limit": 100})
        entries = r.get("entries", [])
        if entries:
            entry = entries[0]
            assert "tool" in entry, "Audit entry must have 'tool' field"
            assert "timestamp" in entry, "Audit entry must have 'timestamp' field"
            assert "success" in entry, "Audit entry must have 'success' field"


class TestOutputDirSecurity:
    """Output directories must be restricted to /results."""

    async def test_output_dir_outside_results(self, mcp_client, test_img):
        r = await _call(mcp_client, "carve_files", {
            "image_path": test_img,
            "output_dir": "/tmp/unauthorized",
        })
        assert not r.get("success"), "Output outside /results should be blocked"


class TestConcurrentAccess:
    """Rapid sequential calls must all succeed."""

    async def test_rapid_sequential_calls(self, mcp_client, test_img):
        calls = [
            ("list_evidence", {"subdir": "cases"}),
            ("verify_hash", {"file_path": test_img, "algorithm": "md5"}),
            ("verify_hash", {"file_path": test_img, "algorithm": "sha1"}),
            ("verify_hash", {"file_path": test_img, "algorithm": "sha256"}),
            ("fs_filesystem_info", {"image_path": test_img}),
        ]
        results = []
        for tool_name, tool_args in calls:
            r = await _call(mcp_client, tool_name, tool_args)
            results.append(r.get("success", False))

        success_count = sum(1 for r in results if r)
        assert success_count == len(results), (
            f"Only {success_count}/{len(results)} rapid sequential calls succeeded"
        )


class TestErrorMessageQuality:
    """Error messages must be descriptive and helpful."""

    async def test_descriptive_error_missing_file(self, mcp_client):
        r = await _call(mcp_client, "fs_partition_scan", {"image_path": "/nonexistent"})
        err_msg = r.get("error", "")
        assert len(err_msg) > 20, f"Error msg too short: '{err_msg}'"

    async def test_descriptive_error_bad_output_dir(self, mcp_client, test_img):
        r = await _call(mcp_client, "carve_files", {
            "image_path": test_img,
            "output_dir": "/tmp/bad",
        })
        err_msg = r.get("error", "")
        assert len(err_msg) > 20, f"Error msg too short: '{err_msg}'"

    async def test_descriptive_error_bad_yara(self, mcp_client, test_img):
        r = await _call(mcp_client, "scan_yara", {"target": test_img, "rules": "bad"})
        err_msg = r.get("error", "")
        assert len(err_msg) > 20, f"Error msg too short: '{err_msg}'"
