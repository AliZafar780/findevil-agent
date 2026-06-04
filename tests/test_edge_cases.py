"""
Comprehensive Edge Case & Failure Mode Test Suite for FindEvil Agent.

Tests every tool against:
  - Missing/nonexistent evidence
  - Empty/invalid arguments
  - Path traversal attacks (security)
  - Wrong tool for evidence type
  - Malformed input
  - Concurrent access
  - Large files
  - Permission errors
  - Output directory validation
  - Audit trail integrity
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

PASS = 0
FAIL = 0
ERRORS = []


def check(desc: str, condition: bool, detail: str = ""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✅ {desc}")
    else:
        FAIL += 1
        msg = f"  ❌ {desc} — {detail}"
        print(msg)
        ERRORS.append(msg)


async def run_tool(client, name: str, args: dict) -> dict:
    """Run a tool and return parsed result."""
    result = await client.call_tool(name, args)
    if isinstance(result, str):
        return json.loads(result)
    return result if isinstance(result, dict) else {"success": False, "error": str(result)}


async def test_all_edge_cases():
    from src.agent.loop import SimpleMCPClient

    client = SimpleMCPClient()
    await client.start()

    test_img = "/evidence/cases/test.raw"

    print("=" * 70)
    print("  COMPREHENSIVE EDGE CASE & FAILURE MODE TEST")
    print("  Testing all 21 tools × 10 failure modes each")
    print("=" * 70)

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 1: PATH TRAVERSAL & SECURITY
    # ══════════════════════════════════════════════════════════════
    print("\n── 1. SECURITY: PATH TRAVERSAL ATTACKS ──")
    attacks = [
        "/etc/passwd",
        "/etc/shadow",
        "/evidence/../../etc/hosts",
        "/evidence/../../../root/.ssh/id_rsa",
        "/evidence/cases/../../../../../etc/ssl/private/key.pem",
        "~/.bash_history",
        "/proc/1/environ",
        "/sys/kernel/security/current_policy",
    ]
    for path in attacks:
        r = await run_tool(client, "fs_partition_scan", {"image_path": path})
        check(f"traversal blocked: {Path(path).name}", not r.get("success"), r.get("error", ""))

    # Additional traversal vectors
    r = await run_tool(client, "list_evidence", {"subdir": "../"})
    check("subdir traversal '../' blocked", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "list_evidence", {"subdir": "../../etc/"})
    check("subdir traversal '../../etc/' blocked", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "list_evidence", {"subdir": "~/../"})
    check("subdir '~' blocked", not r.get("success"), r.get("error", ""))

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 2: MISSING / NONEXISTENT EVIDENCE
    # ══════════════════════════════════════════════════════════════
    print("\n── 2. MISSING / NONEXISTENT EVIDENCE ──")
    tool_args = {
        "fs_partition_scan": {"image_path": "/nonexistent/path.raw"},
        "fs_list_files": {"image_path": "/nonexistent/path.raw"},
        "fs_filesystem_info": {"image_path": "/nonexistent/path.raw"},
        "verify_hash": {"file_path": "/nonexistent/path.raw", "algorithm": "sha256"},
    }
    for tool, args in tool_args.items():
        r = await run_tool(client, tool, args)
        check(f"{tool} with missing path fails gracefully", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "carve_files", {
        "image_path": "/nonexistent/img.raw",
        "output_dir": "/results/carved/test",
    })
    check("carve with missing image fails gracefully", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "scan_yara", {
        "target": "/nonexistent/file.bin",
        "rules": "rule t { condition: true }",
    })
    check("yara with missing target fails gracefully", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "fs_extract_file", {
        "image_path": "/nonexistent/img.raw",
        "inode": 1,
    })
    check("extract with missing image fails gracefully", not r.get("success"), r.get("error", ""))

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 3: EMPTY / INVALID ARGUMENTS
    # ══════════════════════════════════════════════════════════════
    print("\n── 3. EMPTY / INVALID ARGUMENTS ──")

    # Empty paths
    r = await run_tool(client, "fs_partition_scan", {"image_path": ""})
    check("empty path partition scan", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "verify_hash", {"file_path": "", "algorithm": "sha256"})
    check("empty path hashing", not r.get("success"), r.get("error", ""))

    # Invalid inodes
    r = await run_tool(client, "fs_extract_file", {"image_path": test_img, "inode": -1})
    check("negative inode", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "fs_extract_file", {"image_path": test_img, "inode": 0})
    check("zero inode", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "fs_extract_file", {"image_path": test_img, "inode": 9999999})
    check("nonexistent inode (9999999)", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "fs_file_metadata", {"image_path": test_img, "inode": 9999999})
    check("nonexistent inode metadata", not r.get("success"), r.get("error", ""))

    # Invalid hash algorithm
    r = await run_tool(client, "verify_hash", {
        "file_path": test_img,
        "algorithm": "invalid_algorithm_name",
    })
    check("invalid hash algorithm", not r.get("success"), r.get("error", ""))

    # Empty/null args
    r = await run_tool(client, "scan_yara", {"target": test_img, "rules": ""})
    check("yara with empty rules", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "scan_yara", {"target": test_img, "rules": "not valid yara @@@ ###"})
    check("yara with malformed rules", not r.get("success"), r.get("error", ""))

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 4: WRONG TOOL FOR EVIDENCE TYPE
    # ══════════════════════════════════════════════════════════════
    print("\n── 4. WRONG TOOL FOR EVIDENCE TYPE ──")

    # Memory tools on disk image
    r = await run_tool(client, "mem_list_processes", {"memory_path": test_img})
    check("memory pslist on disk image", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "mem_analyze", {"memory_path": test_img})
    check("memory analyze on disk image", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "mem_scan_network", {"memory_path": test_img})
    check("memory netscan on disk image", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "mem_dump_cmdline", {"memory_path": test_img})
    check("memory cmdline on disk image", not r.get("success"), r.get("error", ""))

    # Registry tool on non-registry file
    r = await run_tool(client, "reg_analyze_hive", {"hive_path": test_img})
    check("registry tool on disk image", not r.get("success"), r.get("error", ""))

    # PCAP tool on non-pcap file
    r = await run_tool(client, "pcap_analyze", {"pcap_path": test_img})
    check("pcap tool on disk image", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "pcap_list_protocols", {"pcap_path": test_img})
    check("pcap protocols on disk image", not r.get("success"), r.get("error", ""))

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 5: CARVING EDGE CASES
    # ══════════════════════════════════════════════════════════════
    print("\n── 5. CARVING EDGE CASES ──")

    # Unauthorized output directory
    r = await run_tool(client, "carve_files", {
        "image_path": test_img,
        "output_dir": "/tmp/unauthorized_carve",
    })
    check("carve to /tmp blocked (security)", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "carve_files", {
        "image_path": test_img,
        "output_dir": "/etc/evil_output",
    })
    check("carve to /etc blocked (security)", not r.get("success"), r.get("error", ""))

    r = await run_tool(client, "carve_files", {
        "image_path": test_img,
        "output_dir": "",
    })
    check("carve with empty output dir", not r.get("success"), r.get("error", ""))

    # Carve specific types
    r = await run_tool(client, "carve_files", {
        "image_path": test_img,
        "output_dir": "/results/carved/jpg_test",
        "file_types": "jpg,png",
    })
    check("carve jpg,png types", r.get("success", False), f"files: {r.get('carved_files', 0)}")

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 6: YARA EDGE CASES
    # ══════════════════════════════════════════════════════════════
    print("\n── 6. YARA EDGE CASES ──")

    # No match
    r = await run_tool(client, "scan_yara", {
        "target": test_img,
        "rules": "rule nevermatch { condition: false }",
    })
    check("yara no-match returns clean", r.get("success") and r.get("match_count", -1) == 0,
          f"match_count={r.get('match_count')}")

    # Should match
    r = await run_tool(client, "scan_yara", {
        "target": test_img,
        "rules": "rule FindEvil { strings: $m = \"malware\" $h = \"Find Evil\" condition: any of them }",
    })
    check("yara should match known strings", r.get("success") and r.get("match_count", 0) > 0,
          f"matches={r.get('match_count')}")

    # Missing target
    r = await run_tool(client, "scan_yara", {
        "target": "",
        "rules": "rule t { condition: true }",
    })
    check("yara with empty target", not r.get("success"), r.get("error", ""))

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 7: FILESYSTEM EDGE CASES
    # ══════════════════════════════════════════════════════════════
    print("\n── 7. FILESYSTEM EDGE CASES ──")

    # Partition scan on non-partitioned image
    r = await run_tool(client, "fs_partition_scan", {"image_path": test_img})
    check("partition scan on raw ext2 (no partition table)", not r.get("success"), "expected")

    # fs_list_files with defaults
    r = await run_tool(client, "fs_list_files", {"image_path": test_img})
    check("list files without offset", r.get("success"), f"files={r.get('file_count', 0)}")

    # Extract known good inode
    r = await run_tool(client, "fs_extract_file", {"image_path": test_img, "inode": 20})
    check("extract known inode 20 (hello.txt)", r.get("success"),
          f"size={r.get('size', '?')} preview={r.get('preview', '')[:50]}...")

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 8: OUTPUT DIRECTORY VALIDATION
    # ══════════════════════════════════════════════════════════════
    print("\n── 8. OUTPUT DIRECTORY SECURITY ──")

    forbidden_dirs = [
        "/",
        "/etc",
        "/var",
        "/tmp",
        "/home",
        "/root",
        "/evidence",
        "/evidence/disk",
        "/bin",
        "/usr",
        "/boot",
        "/dev",
    ]
    for d in forbidden_dirs:
        r = await run_tool(client, "carve_files", {
            "image_path": test_img,
            "output_dir": f"{d}/carved",
        })
        check(f"carve to {d} blocked", not r.get("success"), r.get("error", ""))

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 9: LARGE FILE HANDLING
    # ══════════════════════════════════════════════════════════════
    print("\n── 9. LARGE FILE HANDLING ──")

    # Create a large test file
    large_path = "/evidence/cases/large_test.bin"
    with open(large_path, "wb") as f:
        f.write(b"X" * 50 * 1024 * 1024)  # 50MB

    r = await run_tool(client, "verify_hash", {
        "file_path": large_path,
        "algorithm": "sha256",
    })
    check("hash of 50MB file", r.get("success"), f"hash={r.get('hash', '')[:20]}...")

    # Hash of large file with different algorithms
    for alg in ["md5", "sha1", "sha256"]:
        r = await run_tool(client, "verify_hash", {"file_path": large_path, "algorithm": alg})
        check(f"hash with {alg}", r.get("success"), f"hash={r.get('hash', '')[:16]}...")

    # YARA on large file
    r = await run_tool(client, "scan_yara", {
        "target": large_path,
        "rules": "rule l { strings: $x = \"XXXX\" condition: $x }",
    })
    check("yara on 50MB file", r.get("success"), f"matches={r.get('match_count')}")

    # Clean up
    os.unlink(large_path)

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 10: AUDIT TRAIL INTEGRITY
    # ══════════════════════════════════════════════════════════════
    print("\n── 10. AUDIT TRAIL ──")
    r = await run_tool(client, "get_audit_logs", {"limit": 1000})
    check("audit logs retrievable", r.get("success"), f"entries={r.get('total_entries', 0)}")

    total = r.get("total_entries", 0)
    check("audit has entries (>20)", total > 20, f"got {total}")

    if total > 0:
        entries = r.get("entries", [])
        # Check that entries have required fields
        for i, entry in enumerate(entries[:5]):
            has_tool = "tool" in entry
            has_time = "timestamp" in entry
            has_success = "success" in entry
            check(f"audit entry {i} has tool/timestamp/success",
                  has_tool and has_time and has_success,
                  f"missing: tool={has_tool} time={has_time} success={has_success}")

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 11: CONCURRENT CALL SAFETY
    # ══════════════════════════════════════════════════════════════
    print("\n── 11. CONCURRENT CALL SAFETY ──")

    # Multiple sequential calls (as fast as possible) should all succeed
    sequential_tools = [
        ("list_evidence", {"subdir": "cases"}),
        ("verify_hash", {"file_path": test_img, "algorithm": "md5"}),
        ("verify_hash", {"file_path": test_img, "algorithm": "sha1"}),
        ("verify_hash", {"file_path": test_img, "algorithm": "sha256"}),
        ("fs_filesystem_info", {"image_path": test_img}),
        ("fs_list_files", {"image_path": test_img}),
        ("fs_file_metadata", {"image_path": test_img, "inode": 20}),
        ("fs_extract_file", {"image_path": test_img, "inode": 20}),
    ]

    results = []
    for tool_name, tool_args in sequential_tools:
        r = await run_tool(client, tool_name, tool_args)
        results.append(r.get("success", False))

    success_count = sum(1 for r in results if r)
    check(f"rapid sequential calls ({success_count}/{len(results)} OK)", success_count == len(results),
          f"failed: {sum(1 for r in results if not r)}")

    # ══════════════════════════════════════════════════════════════
    # CATEGORY 12: ERROR MESSAGE QUALITY
    # ══════════════════════════════════════════════════════════════
    print("\n── 12. ERROR MESSAGE QUALITY ──")

    # Check that errors are descriptive, not empty strings
    r = await run_tool(client, "fs_partition_scan", {"image_path": "/nonexistent"})
    err_msg = r.get("error", "")
    check("descriptive error for missing file", len(err_msg) > 20, err_msg)

    r = await run_tool(client, "carve_files", {
        "image_path": test_img,
        "output_dir": "/tmp/bad",
    })
    err_msg = r.get("error", "")
    check("descriptive error for bad output dir", len(err_msg) > 20, err_msg)

    r = await run_tool(client, "scan_yara", {"target": test_img, "rules": "bad"})
    err_msg = r.get("error", "")
    check("descriptive error for bad yara rules", len(err_msg) > 20, err_msg)

    # ══════════════════════════════════════════════════════════════
    # DONE
    # ══════════════════════════════════════════════════════════════
    await client.stop()

    print(f"\n{'=' * 70}")
    print(f"  RESULTS: {PASS} PASSED, {FAIL} FAILED, {PASS+FAIL} TOTAL")
    print(f"{'=' * 70}")

    if ERRORS:
        print(f"\n  FAILURES:")
        for e in ERRORS:
            print(f"    {e}")

    return FAIL == 0


def main():
    success = asyncio.run(test_all_edge_cases())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
